use std::{
    fs::File,
    io::{BufWriter, Read, Write},
    path::Path,
};

use clap::Parser;

use args::{DecryptCommand, LsCommand};
use rustcryptfs_lib::GocryptFs;

#[cfg(feature = "mount")]
#[cfg(any(target_os = "linux", target_os = "windows"))]
use args::MountCommand;

mod args;

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = args::Args::parse();

    match &args.command {
        args::Commands::Decrypt(c) => decrypt_file(c),
        args::Commands::Ls(c) => ls(c),
        #[cfg(feature = "mount")]
        #[cfg(any(target_os = "linux", target_os = "windows"))]
        args::Commands::Mount(c) => mount(c),
    }
}

fn ls(c: &LsCommand) -> anyhow::Result<()> {
    let folder_path = Path::new(&c.folder_path);

    let password = if let Some(password) = &c.password {
        password.clone()
    } else {
        rpassword::prompt_password("Your password: ")?
    };

    let fs = GocryptFs::open(
        c.gocryptfs_path
            .as_ref()
            .map(Path::new)
            .unwrap_or(folder_path),
        &password,
    )?;

    let filename_decoder = fs.filename_decoder();

    let iv = std::fs::read(folder_path.join("gocryptfs.diriv"))?;

    let dir_decoder = filename_decoder.get_cipher_for_dir(&iv);

    for dir in std::fs::read_dir(folder_path)?.flat_map(|e| e.ok()) {
        let filename = dir.file_name();
        let filename = filename.to_string_lossy();

        if filename != "gocryptfs.conf" && filename != "gocryptfs.diriv" {
            if filename.starts_with("gocryptfs.longname.") {
                if !filename.ends_with(".name") {
                    let filename =
                        std::fs::read_to_string(folder_path.join(format!("{}.name", filename)))?;
                    if let Ok(res) = dir_decoder.decode_filename(filename) {
                        println!("{}", res);
                    }
                }
            } else if let Ok(res) = dir_decoder.decode_filename(&*filename) {
                println!("{}", res);
            }
        }
    }

    Ok(())
}

fn decrypt_file(c: &DecryptCommand) -> anyhow::Result<()> {
    let file_path = Path::new(&c.file_path);

    let password = if let Some(password) = &c.password {
        password.clone()
    } else {
        rpassword::prompt_password("Your password: ")?
    };

    let fs = GocryptFs::open(
        c.gocryptfs_path
            .as_ref()
            .map(Path::new)
            .unwrap_or_else(|| file_path.parent().unwrap()),
        &password,
    )?;

    let mut file = File::open(file_path)?;

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

        if res.is_empty() {
            break;
        }

        block_index += 1;
    }
    stdout.flush()?;

    Ok(())
}

#[cfg(target_os = "linux")]
#[cfg(feature = "mount")]
fn mount(mount: &MountCommand) -> anyhow::Result<()> {
    use anyhow::Context;

    let password = if let Some(password) = &mount.password {
        password.clone()
    } else {
        rpassword::prompt_password("Your password: ")?
    };

    rustcryptfs_mount::mount(&mount.path, &mount.mountpoint, &password)
        .context("Failed to run fuse fs")?;

    Ok(())
}

#[cfg(target_os = "windows")]
#[cfg(feature = "mount")]
fn mount(mount: &MountCommand) -> anyhow::Result<()> {
    unimplemented!()
}
