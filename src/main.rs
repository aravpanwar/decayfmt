//! decayfmt command line entry point.
//!
//! This layer only parses arguments and delegates to the module that does the
//! work. It holds no business logic: encoding lives in encode.rs. Its one extra
//! responsibility is presentation, since library functions return errors rather
//! than printing them; this is the single place a decayfmt error is shown to the
//! user and turned into a non-zero exit code.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

/// The decayfmt CLI: encode source files into decaying files.
#[derive(Parser)]
#[command(
    name = "decayfmt",
    version,
    about = "A file format where opening a file corrupts it."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// The subcommands decayfmt exposes.
#[derive(Subcommand)]
enum Command {
    /// Encode a source image, text, or audio file into a decayfmt file.
    Encode {
        /// Path to the source image, text, or audio file to encode.
        #[arg(long)]
        input: PathBuf,
        /// Path to write the decayfmt file to, ending in .idcy<x>, .tdcy<x>, or
        /// .adcy<x>. The instability value x is taken from this name; higher x
        /// decays faster.
        #[arg(long)]
        output: PathBuf,
    },
    /// Open a decayfmt file: corrupt it in place on disk, then display or play it.
    Open {
        /// Path to the decayfmt file to open. x is read from its extension.
        file: PathBuf,
    },
}

/// Parses the command line and runs the chosen subcommand. On error, prints the
/// typed decayfmt error and exits with a failure code; on success, exits cleanly.
fn main() -> ExitCode {
    let cli = Cli::parse();

    // Sweep the temporary files left by the last display before doing anything else.
    // Running this for every command, rather than only inside open, means an encode or
    // a failed open also clears the snapshot of a past decay state that the previous
    // display left in the temp directory.
    decayfmt::open::sweep_stale_view_files();

    let result = match cli.command {
        Command::Encode { input, output } => decayfmt::encode::encode_file(&input, &output),
        Command::Open { file } => decayfmt::open::open_file(&file),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", error);
            ExitCode::FAILURE
        }
    }
}
