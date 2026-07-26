use std::{fs::File, io, path::Path};

use rnmdb_common::error::{ErrorKind, Result, RnovError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SourceIdentity {
    namespace: u64,
    file: u64,
}

pub(super) fn open_rekey_source(path: &Path) -> Result<(File, SourceIdentity)> {
    let file = open_source_file(path)?;
    let identity = validate_open_source(&file)?;
    Ok((file, identity))
}

#[cfg(unix)]
fn open_source_file(path: &Path) -> Result<File> {
    use rustix::fs::{Mode, OFlags, open};
    use rustix::io::Errno;

    match open(
        path,
        OFlags::RDWR | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    ) {
        Ok(file) => Ok(file.into()),
        Err(Errno::LOOP) => Err(symbolic_link_error()),
        Err(error) => Err(source_open_error(error.into())),
    }
}

#[cfg(windows)]
fn open_source_file(path: &Path) -> Result<File> {
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    options.open(path).map_err(source_open_error)
}

#[cfg(not(any(unix, windows)))]
fn open_source_file(_path: &Path) -> Result<File> {
    Err(unsupported_platform_error())
}

#[cfg(unix)]
fn validate_open_source(file: &File) -> Result<SourceIdentity> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata().map_err(source_metadata_error)?;
    validate_source_file_shape(metadata.is_file(), metadata.nlink())?;
    Ok(SourceIdentity {
        namespace: metadata.dev(),
        file: metadata.ino(),
    })
}

#[cfg(windows)]
fn validate_open_source(file: &File) -> Result<SourceIdentity> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    };

    let information = windows_file_information(file)?;
    let disallowed_attributes = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT;
    let is_regular = information.file_attributes & disallowed_attributes == 0;
    validate_source_file_shape(is_regular, u64::from(information.number_of_links))?;
    Ok(SourceIdentity {
        namespace: u64::from(information.volume_serial_number),
        file: information.file_index,
    })
}

#[cfg(not(any(unix, windows)))]
fn validate_open_source(_file: &File) -> Result<SourceIdentity> {
    Err(unsupported_platform_error())
}

#[cfg(windows)]
struct WindowsFileInformation {
    file_attributes: u32,
    volume_serial_number: u32,
    number_of_links: u32,
    file_index: u64,
}

#[cfg(windows)]
fn windows_file_information(file: &File) -> Result<WindowsFileInformation> {
    use std::{mem::MaybeUninit, os::windows::io::AsRawHandle};
    use windows_sys::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
    };

    // SAFETY: `file` owns a valid handle for the duration of the call, and the
    // OS initializes the output structure completely before reporting success.
    let information = unsafe {
        let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
        let succeeded =
            GetFileInformationByHandle(file.as_raw_handle() as HANDLE, information.as_mut_ptr());
        if succeeded == 0 {
            return Err(source_metadata_error(io::Error::last_os_error()));
        }
        information.assume_init()
    };
    Ok(WindowsFileInformation {
        file_attributes: information.dwFileAttributes,
        volume_serial_number: information.dwVolumeSerialNumber,
        number_of_links: information.nNumberOfLinks,
        file_index: (u64::from(information.nFileIndexHigh) << 32)
            | u64::from(information.nFileIndexLow),
    })
}

fn validate_source_file_shape(is_regular: bool, links: u64) -> Result<()> {
    if !is_regular {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "rekey source must be a regular file and cannot be a symbolic link",
        ));
    }
    if links > 1 {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "single-file rekey rejects hard links because another name would retain old-key ciphertext",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn symbolic_link_error() -> RnovError {
    RnovError::new(
        ErrorKind::InvalidInput,
        "rekey source cannot be a symbolic link",
    )
}

fn source_open_error(error: io::Error) -> RnovError {
    RnovError::new(
        ErrorKind::Io,
        format!("failed to open database file for rekey: {error}"),
    )
}

fn source_metadata_error(error: io::Error) -> RnovError {
    RnovError::new(
        ErrorKind::Io,
        format!("failed to inspect opened rekey source: {error}"),
    )
}

#[cfg(not(any(unix, windows)))]
fn unsupported_platform_error() -> RnovError {
    RnovError::new(
        ErrorKind::Storage,
        "single-file rekey cannot verify source identity on this platform",
    )
}
