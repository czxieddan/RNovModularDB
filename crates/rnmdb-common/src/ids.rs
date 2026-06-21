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
