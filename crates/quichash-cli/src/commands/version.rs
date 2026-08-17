use quichash_core::error::HashUtilityError;

/// Handle the version command: display version information
pub fn handle_version_command() -> Result<(), HashUtilityError> {
    // Get version from Cargo.toml at compile time
    const VERSION: &str = env!("CARGO_PKG_VERSION");

    // Display version in the format: hash v{version}
    println!("hash v{}", VERSION);

    Ok(())
}
