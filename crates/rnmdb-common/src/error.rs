use std::{error::Error, fmt};

pub type Result<T> = std::result::Result<T, RnovError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    Canceled,
    Config,
    Corruption,
    Internal,
    InvalidInput,
    Io,
    NotFound,
    Security,
    Storage,
}

pub struct RnovError {
    kind: ErrorKind,
    message: String,
    private_context: Option<String>,
}

impl RnovError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            private_context: None,
        }
    }

    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    pub fn with_private_context(mut self, context: impl Into<String>) -> Self {
        self.private_context = Some(context.into());
        self
    }
}

impl fmt::Display for RnovError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl fmt::Debug for RnovError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RnovError")
            .field("kind", &self.kind)
            .field("message", &self.message)
            .field(
                "private_context",
                &self.private_context.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl Error for RnovError {}
