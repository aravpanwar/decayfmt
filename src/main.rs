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
    /// Optional TSS2 TCTI configuration to connect to, for example
    /// `swtpm:host=127.0.0.1,port=2321`. When omitted the default TPM device
    /// (`/dev/tpmrm0`) is used. Only affects v2 (bare `.idcy`/`.tdcy`) files.
    #[arg(long, global = true)]
    tcti: Option<String>,

    #[command(subcommand)]
    command: Command,
}

/// The subcommands decayfmt exposes.
#[derive(Subcommand)]
enum Command {
    /// Encode a source image or text file into a decayfmt file.
    Encode {
        /// Path to the source image or text file to encode.
        #[arg(long)]
        input: PathBuf,
        /// Path to write the decayfmt file to. Ending in .idcy<x> or .tdcy<x> produces a v1
        /// file (the default); the instability value x is taken from the v1 name and higher x
        /// decays faster. A bare .idcy/.tdcy (no decay suffix) name produces the v2, TPM-bound
        /// file and requires -v2.
        #[arg(long)]
        output: PathBuf,
        /// Maximum number of opens for a v2 output (default 10). Requires -v2 and a bare
        /// .idcy/.tdcy output name; must be greater than zero.
        #[arg(long, requires = "v2")]
        max_opens: Option<u32>,
        /// Opt into the TPM-backed v2 format: an encrypted, hardware-bound file whose decay
        /// is enforced by a TPM monotonic counter. Only v2 output names (bare .idcy/.tdcy)
        /// may be used with it.
        #[arg(long)]
        v2: bool,
    },
    /// Open a decayfmt file: corrupt it in place on disk, then display it.
    Open {
        /// Path to the decayfmt file to open. x is read from its extension.
        file: PathBuf,
    },
}

/// Parses the command line and runs the chosen subcommand. On error, prints the
/// typed decayfmt error and exits with a failure code; on success, exits cleanly.
fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Encode {
            input,
            output,
            max_opens,
            v2,
        } => decayfmt::encode::encode(&input, &output, max_opens, v2, cli.tcti.as_deref()),
        Command::Open { file } => decayfmt::open::open_file(&file, cli.tcti.as_deref()),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
