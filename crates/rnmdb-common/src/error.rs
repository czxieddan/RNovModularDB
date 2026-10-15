// crates/rnmdb-common/src/error.rs - RNovModularDB source module.
// Copyright (C) 2026 czxieddan
//
// The AHCL-covered material identified below forms part of
// RNovModularDB and is provided under version 1.2 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also subject
// to the AHCL provisions concerning Continuous AHCL Licensing Segments and
// migration to later official versions.
//
// AHCL-covered portions: the whole file
//
// Subject to Section 3.1 of AHCL, after having a reasonable opportunity to
// read AHCL, all applicable Additional Restrictions, and all version notices,
// a person accepts the corresponding terms by engaging in Use of the
// AHCL-covered material identified above. Any separate or affirmative assent
// required by applicable mandatory law must still be obtained.
//
// License notice updated: October 15, 2026.
// Official AHCL text and public notices: https://ahcl.aperip.com
// Applicable LICENSE: LICENSE
// Paths below are relative to the directory containing that LICENSE.
// AHCL Materials Directory: .ahcl/
// Repository official or recognized AHCL copy: .ahcl/AHCL-1.2.md
// Canonical repository: https://github.com/czxieddan/RNovModularDB
// Project notice: .ahcl/AHCL-PROJECT-NOTICE.md
// Version records: .ahcl/AHCL-VERSION-ADOPTION.md
// Source and history: .ahcl/AHCL-SOURCE.md
// Dependencies and licenses: .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions: None.
// SPDX-License-Identifier: LicenseRef-AHCL-1.2
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
