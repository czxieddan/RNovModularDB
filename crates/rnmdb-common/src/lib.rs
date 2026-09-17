// crates/rnmdb-common/src/lib.rs - RNovModularDB source module.
// Copyright (C) 2026 czxieddan
// This file is part of RNovModularDB and is provided under version 1.1 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also
// subject to the AHCL provisions concerning Continuous AHCL Licensing Segments
// and migration to later official versions. After a reasonable opportunity to
// read AHCL, all applicable Additional Restrictions, and all version notices,
// use, copying, modification, building, dependency use, deployment,
// distribution, or network operation constitutes acceptance to the extent
// permitted by applicable law.
// License notice updated: September 17, 2026.
// Official AHCL text and public notices: https://ahcl.aperip.com
// AHCL Materials Directory: .ahcl/
// Repository official or recognized AHCL copy: .ahcl/AHCL-1.1.md
// Canonical repository: https://github.com/czxieddan/RNovModularDB
// Project notice: .ahcl/AHCL-PROJECT-NOTICE.md
// Version records: .ahcl/AHCL-VERSION-ADOPTION.md
// Source and history: .ahcl/AHCL-SOURCE.md
// Dependencies and licenses: .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions: None.
// SPDX-License-Identifier: LicenseRef-AHCL-1.1
pub mod config;
pub mod error;
pub mod ids;
pub mod metrics;

pub use error::{ErrorKind, Result, RnovError};
