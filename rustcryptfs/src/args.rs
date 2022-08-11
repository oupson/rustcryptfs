use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
pub(crate) struct Args {
    #[clap(subcommand)]
    pub(crate) command: Commands,
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    /// Decrypt a file
    Decrypt(DecryptCommand),

    // List file contained in a directory
    Ls(LsCommand),
}

#[derive(Debug, Parser)]
pub(crate) struct DecryptCommand {
    /// The file to decrypt
    pub(crate) file_path : String,

    /// Path to the gocryptfs directory
    #[clap(short('g'), long)]
    pub(crate) gocryptfs_path : Option<String>,

    /// The password
    #[clap(short, long)]
    pub(crate) password : Option<String>
}

#[derive(Debug, Parser)]
pub(crate) struct LsCommand {
    /// The directory
    pub(crate) folder_path : String,

    /// Path to the gocryptfs directory
    #[clap(short('g'), long)]
    pub(crate) gocryptfs_path : Option<String>,

    /// The password
    #[clap(short, long)]
    pub(crate) password : Option<String>
}