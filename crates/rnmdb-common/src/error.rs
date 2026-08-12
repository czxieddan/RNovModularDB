// crates/rnmdb-common/src/error.rs - RNovModularDB source module.
// Copyright (C) 2026 czxieddan
// This file is part of RNovModularDB and is provided under version 1.0 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also
// subject to the AHCL provisions concerning Continuous AHCL Licensing Segments
// and migration to later official versions. After a reasonable opportunity to
// read AHCL, all applicable Additional Restrictions, and all version notices,
// use, copying, modification, building, dependency use, deployment,
// distribution, or network operation constitutes acceptance to the extent
// permitted by applicable law.
// License notice updated: August 12, 2026.
// Official text and notices: https://ahcl.aperip.com
// Repository license copy: AHCL/AHCL-1.0.md
// Canonical repository: https://github.com/czxieddan/RNovModularDB
// Project notice: AHCL/AHCL-PROJECT-NOTICE.md
// Version records: AHCL/AHCL-VERSION-ADOPTION.md
// Source and history: AHCL/AHCL-SOURCE.md
// Dependencies and licenses: AHCL/AHCL-DEPENDENCIES.md
// Additional Restrictions: None.
// SPDX-License-Identifier: LicenseRef-AHCL-1.0
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
