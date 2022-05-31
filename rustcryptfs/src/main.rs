use std::{
    fs::{self, File},
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::Context;
use clap::Parser;

use args::{DecryptCommand, LsCommand};
use rustcryptfs_lib::{config::{self, CryptConf}, filename::FilenameDecoder, content_enc::ContentEnc};

mod args;

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = args::Args::parse();
    log::debug!("{:?}", args);

    match &args.command {
        args::Commands::Decrypt(c) => decrypt_file(c),
        args::Commands::Ls(c) => ls(c),
    }
}

fn ls(c: &LsCommand) -> anyhow::Result<()> {
    let folder_path = Path::new(&c.folder_path);
    let config_path = c
        .gocryptfs_conf_path
        .as_ref()
        .map(|p| PathBuf::from(p))
        .unwrap_or_else(|| folder_path.join("gocryptfs.conf"));

    let content = fs::read_to_string(config_path)?;

    let conf: CryptConf =
        serde_json::from_str(&content).context("Failed to decode configuration")?;

    let master_key = conf.get_master_key(c.password.as_ref().unwrap().as_bytes()).context("Failed to get master key")?;

    let filename_decoder = FilenameDecoder::new(&master_key)?;

    let iv = std::fs::read(folder_path.join("gocryptfs.diriv"))?;

    let dir_decoder = filename_decoder.get_decoder_for_dir(&iv);

    for dir in std::fs::read_dir(folder_path)?.flat_map(|e| e.ok()) {
        let filename = dir.file_name();
        let filename = filename.to_str().unwrap();

        if filename != "."
            && filename != ".."
            && filename != "gocryptfs.conf"
            && filename != "gocryptfs.diriv"
        {
            if filename.starts_with("gocryptfs.longname.") {
                if !filename.ends_with(".name") {
                    let filename = std::fs::read_to_string(folder_path.join(format!("{}.name", filename)))?;
                    if let Ok(res) = dir_decoder.decode_filename(&filename) {
                        println!("{}", res);
                    }
                }
            } else {
                if let Ok(res) = dir_decoder.decode_filename(&filename) {
                    println!("{}", res);
                }
            };
        }
    }

    return Ok(());
}

fn decrypt_file(c: &DecryptCommand) -> anyhow::Result<()> {
    let file_path = Path::new(&c.file_path);
    let config_path = c
        .gocryptfs_conf_path
        .as_ref()
        .map(|p| PathBuf::from(p))
        .unwrap_or_else(|| file_path.parent().unwrap().join("gocryptfs.conf"));

    let content = fs::read_to_string(config_path)?;

    let conf: config::CryptConf =
        serde_json::from_str(&content).context("Failed to decode configuration")?;

    let mut file = File::open(file_path).unwrap();

    let master_key = conf.get_master_key(c.password.as_ref().unwrap().as_bytes())?;

    let enc = ContentEnc::new(&master_key, 16);

    let mut buf = [0u8; 18];
    let n = file.read(&mut buf)?;
    let id = if n < 18 { None } else { Some(&buf[2..]) };

    let mut buf = [0u8; 4096 + 32];
    let stdout = std::io::stdout();
    let mut stdout = BufWriter::new(stdout.lock());

    let mut block_index = 0;
    loop {
        let n = file.read(&mut buf)?;
        let res = enc.decrypt_block(&buf[..n], block_index, id)?;

        stdout.write_all(&res)?;

        if res.len() == 0 {
            break;
        }

        block_index += 1;
    }
    stdout.flush()?;

    Ok(())
}
