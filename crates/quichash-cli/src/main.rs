mod cli;
mod commands;

use std::io::IsTerminal;
use std::process;

use cli::{Command, parse_args};
use commands::*;

fn main() {
    // Parse command-line arguments
    let cli = match parse_args() {
        Ok(cli) => cli,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    // Check if running with no arguments and stdin is a terminal (not piped)
    // If so, show help instead of waiting for stdin
    if cli.command.is_none()
        && cli.file.is_none()
        && cli.text.is_none()
        && std::io::stdin().is_terminal()
    {
        // Show full help by simulating --help flag
        use clap::CommandFactory;
        let mut cmd = cli::Cli::command();
        cmd.print_help().unwrap();
        println!(); // Add newline after help
        process::exit(0);
    }

    // Dispatch to appropriate handler
    let result = match cli.command {
        Some(Command::Scan {
            directory,
            algorithm,
            database,
            hdd,
            fast,
            format,
            json,
            compress,
        }) => handle_scan_command(
            &directory, &algorithm, &database, !hdd, fast, &format, json, compress,
        ),
        Some(Command::Verify {
            database,
            directory,
            hdd,
            json,
        }) => handle_verify_command(&database, &directory, !hdd, json),
        Some(Command::Benchmark { size_mb, json }) => handle_benchmark_command(size_mb, json),
        Some(Command::List { json }) => handle_list_command(json),
        Some(Command::Compare {
            database1,
            database2,
            output,
            format,
        }) => handle_compare_command(&database1, &database2, output.as_deref(), &format),
        Some(Command::Version) => handle_version_command(),
        Some(Command::Dedup {
            directory,
            fast,
            output,
            json,
        }) => handle_dedup_command(&directory, fast, output.as_deref(), json),
        Some(Command::Analyze {
            database,
            json,
            output,
        }) => handle_analyze_command(&database, json, output.as_deref()),
        None => {
            // No subcommand means hash mode (default)
            handle_hash_command(
                cli.file.as_deref(),
                cli.text.as_deref(),
                &cli.algorithms,
                cli.output.as_deref(),
                cli.fast,
                cli.json,
            )
        }
    };

    // Handle errors
    if let Err(e) = result {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
