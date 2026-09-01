use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

use super::HashMode;

/// Open a hashing input with the best non-binding cache hint available on the
/// current platform. Unsupported filesystems behave like `File::open`.
pub(crate) fn open(path: &Path, mode: HashMode) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(windows)]
    if mode == HashMode::Full {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_SEQUENTIAL_SCAN;
        options.custom_flags(FILE_FLAG_SEQUENTIAL_SCAN);
    }

    let file = options.open(path)?;
    advise(&file, mode);
    Ok(file)
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
#[allow(unsafe_code)]
fn advise(file: &File, mode: HashMode) {
    use std::os::fd::AsRawFd;

    let advice = match mode {
        HashMode::Full => libc::POSIX_FADV_SEQUENTIAL,
        HashMode::Sampled => libc::POSIX_FADV_RANDOM,
    };
    // SAFETY: `file` owns a live descriptor for the duration of this advisory
    // call. Offset and length select the complete file.
    let _ = unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, advice) };
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn advise(file: &File, mode: HashMode) {
    use std::os::fd::AsRawFd;

    if mode == HashMode::Full {
        // SAFETY: `file` owns a live descriptor and F_RDAHEAD consumes only an
        // integer enable flag without retaining any borrowed state.
        let _ = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_RDAHEAD, 1) };
    }
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
fn advise(_file: &File, _mode: HashMode) {}
