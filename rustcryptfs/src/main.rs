use std::{
    fs::File,
    io::{BufWriter, Read, Write},
    path::Path,
};

use clap::Parser;

use args::{DecryptCommand, LsCommand, MountCommand};
use rustcryptfs_lib::GocryptFs;

mod args;

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = args::Args::parse();
    log::debug!("{:?}", args);

    match &args.command {
        args::Commands::Decrypt(c) => decrypt_file(c),
        args::Commands::Ls(c) => ls(c),
        args::Commands::Mount(c) => mount(c),
    }
}

fn ls(c: &LsCommand) -> anyhow::Result<()> {
    let folder_path = Path::new(&c.folder_path);

    let fs = GocryptFs::open(
        c.gocryptfs_path
            .as_ref()
            .map(|p| Path::new(p))
            .unwrap_or(folder_path),
        c.password.as_ref().expect("Please input a password"),
    )?;

    let filename_decoder = fs.filename_decoder();

    let iv = std::fs::read(folder_path.join("gocryptfs.diriv"))?;

    let dir_decoder = filename_decoder.get_decoder_for_dir(&iv);

    for dir in std::fs::read_dir(folder_path)?.flat_map(|e| e.ok()) {
        let filename = dir.file_name();
        let filename = filename.to_str().unwrap();

        if filename != "gocryptfs.conf" && filename != "gocryptfs.diriv" {
            if filename.starts_with("gocryptfs.longname.") {
                if !filename.ends_with(".name") {
                    let filename =
                        std::fs::read_to_string(folder_path.join(format!("{}.name", filename)))?;
                    if let Ok(res) = dir_decoder.decode_filename(filename) {
                        println!("{}", res);
                    }
                }
            } else {
                if let Ok(res) = dir_decoder.decode_filename(filename) {
                    println!("{}", res);
                }
            };
        }
    }

    return Ok(());
}

fn decrypt_file(c: &DecryptCommand) -> anyhow::Result<()> {
    let file_path = Path::new(&c.file_path);
    let fs = GocryptFs::open(
        c.gocryptfs_path
            .as_ref()
            .map(|p| Path::new(p))
            .unwrap_or_else(|| file_path.parent().unwrap()),
        c.password.as_ref().expect("Please input a password"),
    )?;

    let mut file = File::open(file_path).unwrap();

    let enc = fs.content_decoder();

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

#[cfg(target_os = "linux")]
fn mount(mount: &MountCommand) -> anyhow::Result<()> {
    use rustcryptfs_linux::EncryptedFs;

    let fs = EncryptedFs::new(&mount.path);

    fs.mount(&mount.mountpoint);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn mount(mount: &MountCommand) -> anyhow::Result<()> {
    unimplemented!()
}
