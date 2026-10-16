use std::{
    env,
    fs::File,
    io::{self, Read},
    path::{Path, PathBuf},
};

use rnmdb_storage::PageCryptoKey;

pub(super) const PAGE_KEY_ENVIRONMENT_VARIABLE: &str = "RNMDB_PAGE_KEY_HEX";
const MAX_PAGE_KEY_INPUT_BYTES: usize = 68;

pub(super) enum PageKeySource {
    Stdin,
    Environment,
    File(PathBuf),
}

struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

pub(super) fn page_key_from_source(source: PageKeySource) -> rnmdb_common::Result<PageCryptoKey> {
    let secret = match source {
        PageKeySource::Stdin => read_page_key_stdin(),
        PageKeySource::Environment => read_page_key_environment(),
        PageKeySource::File(path) => read_page_key_file(&path),
    }?;
    parse_page_key_secret(&secret)
}

fn read_page_key_stdin() -> rnmdb_common::Result<SecretBytes> {
    let stdin = io::stdin();
    read_bounded_page_key(stdin.lock(), "standard input")
}

fn read_page_key_environment() -> rnmdb_common::Result<SecretBytes> {
    match env::var(PAGE_KEY_ENVIRONMENT_VARIABLE) {
        Ok(value) => bounded_page_key(value.into_bytes(), PAGE_KEY_ENVIRONMENT_VARIABLE),
        Err(env::VarError::NotPresent) => Err(rnmdb_common::RnovError::new(
            rnmdb_common::ErrorKind::InvalidInput,
            format!("{PAGE_KEY_ENVIRONMENT_VARIABLE} is not set"),
        )),
        Err(env::VarError::NotUnicode(_)) => Err(rnmdb_common::RnovError::new(
            rnmdb_common::ErrorKind::InvalidInput,
            format!("{PAGE_KEY_ENVIRONMENT_VARIABLE} is not valid UTF-8"),
        )),
    }
}

fn read_page_key_file(path: &Path) -> rnmdb_common::Result<SecretBytes> {
    let file = File::open(path).map_err(|err| {
        rnmdb_common::RnovError::new(
            rnmdb_common::ErrorKind::Io,
            format!("failed to open page key file '{}': {err}", path.display()),
        )
    })?;
    read_bounded_page_key(file, "page key file")
}

fn read_bounded_page_key(reader: impl Read, source: &str) -> rnmdb_common::Result<SecretBytes> {
    let mut bytes = Vec::with_capacity(MAX_PAGE_KEY_INPUT_BYTES + 1);
    reader
        .take((MAX_PAGE_KEY_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|err| {
            rnmdb_common::RnovError::new(
                rnmdb_common::ErrorKind::Io,
                format!("failed to read page key from {source}: {err}"),
            )
        })?;
    bounded_page_key(bytes, source)
}

fn bounded_page_key(bytes: Vec<u8>, source: &str) -> rnmdb_common::Result<SecretBytes> {
    let secret = SecretBytes(bytes);
    if secret.as_slice().len() <= MAX_PAGE_KEY_INPUT_BYTES {
        return Ok(secret);
    }
    Err(rnmdb_common::RnovError::new(
        rnmdb_common::ErrorKind::InvalidInput,
        format!("page key from {source} exceeds the maximum supported length"),
    ))
}

fn parse_page_key_secret(secret: &SecretBytes) -> rnmdb_common::Result<PageCryptoKey> {
    let bytes = strip_one_line_ending(secret.as_slice());
    let hex = std::str::from_utf8(bytes).map_err(|_| {
        rnmdb_common::RnovError::new(
            rnmdb_common::ErrorKind::InvalidInput,
            "page key input is not valid UTF-8",
        )
    })?;
    rnmdb_cli::page_key_from_hex(hex)
}

fn strip_one_line_ending(bytes: &[u8]) -> &[u8] {
    if let Some(bytes) = bytes.strip_suffix(b"\r\n") {
        return bytes;
    }
    bytes.strip_suffix(b"\n").unwrap_or(bytes)
}
