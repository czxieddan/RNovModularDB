// crates/rnmdb-common/src/ids.rs - RNovModularDB source module.
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
use std::fmt;

macro_rules! typed_id {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(u64);

        impl $name {
            pub const fn new(value: u64) -> Self {
                Self(value)
            }

            pub const fn get(self) -> u64 {
                self.0
            }
        }

        impl From<u64> for $name {
            fn from(value: u64) -> Self {
                Self::new(value)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}:{}", $prefix, self.0)
            }
        }
    };
}

typed_id!(DatabaseId, "db");
typed_id!(FunctionId, "fn");
typed_id!(InstanceId, "inst");
typed_id!(OperatorId, "op");
typed_id!(PageId, "page");
typed_id!(PolicyId, "policy");
typed_id!(RelationId, "rel");
typed_id!(RoleId, "role");
typed_id!(SnapshotId, "snap");
typed_id!(TransactionId, "txn");
