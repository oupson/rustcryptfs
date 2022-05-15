use std::{
    fs::{self, File},
    io::{BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use anyhow::Context;
use args::DecryptCommand;
use clap::Parser;

use crate::content_enc::ContentEnc;

mod args;
mod config;
mod content_enc;

fn main() -> anyhow::Result<()> {
    let args = args::Args::parse();
    log::debug!("{:?}", args);

    match &args.command {
        args::Commands::Decrypt(c) => decrypt_file(c),
    }
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
