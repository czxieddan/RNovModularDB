use std::collections::BTreeSet;

use rnovdb_common::{
    ErrorKind, Result, RnovError,
    ids::{InstanceId, RelationId, RoleId},
};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditEventKind {
    Authentication,
    Authorization,
    PrivilegeChange,
    PolicyChange,
    KeyEvent,
    Ddl,
    BackupRestore,
    DeniedAccess,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ObjectPrivilege {
    Select,
    Insert,
    Update,
    Delete,
    Execute,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RelationGrant {
    role_id: RoleId,
    relation_id: RelationId,
    privilege: ObjectPrivilege,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccessControl {
    relation_grants: BTreeSet<RelationGrant>,
}

impl AccessControl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn grant_relation_privilege(
        &mut self,
        role_id: RoleId,
        relation_id: RelationId,
        privilege: ObjectPrivilege,
    ) -> bool {
        self.relation_grants.insert(RelationGrant {
            role_id,
            relation_id,
            privilege,
        })
    }

    pub fn revoke_relation_privilege(
        &mut self,
        role_id: RoleId,
        relation_id: RelationId,
        privilege: ObjectPrivilege,
    ) -> bool {
        self.relation_grants.remove(&RelationGrant {
            role_id,
            relation_id,
            privilege,
        })
    }

    pub fn has_relation_privilege(
        &self,
        role_id: RoleId,
        relation_id: RelationId,
        privilege: ObjectPrivilege,
    ) -> bool {
        self.relation_grants.contains(&RelationGrant {
            role_id,
            relation_id,
            privilege,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRecord {
    instance_id: InstanceId,
    role_id: Option<RoleId>,
    sequence: u64,
    kind: AuditEventKind,
    message: String,
    previous_digest: AuditDigest,
    digest: AuditDigest,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuditDigest([u8; 32]);

impl AuditDigest {
    pub const fn zero() -> Self {
        Self([0_u8; 32])
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(64);
        for byte in self.0 {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }
}

impl AuditRecord {
    pub fn new(
        instance_id: InstanceId,
        role_id: Option<RoleId>,
        sequence: u64,
        kind: AuditEventKind,
        message: impl Into<String>,
        previous_digest: AuditDigest,
    ) -> Result<Self> {
        let message = message.into();
        if message.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "audit message cannot be empty",
            ));
        }

        let digest = audit_digest(
            instance_id,
            role_id,
            sequence,
            &kind,
            message.as_bytes(),
            previous_digest,
        );
        Ok(Self {
            instance_id,
            role_id,
            sequence,
            kind,
            message,
            previous_digest,
            digest,
        })
    }

    pub fn verify(&self) -> bool {
        self.digest
            == audit_digest(
                self.instance_id,
                self.role_id,
                self.sequence,
                &self.kind,
                self.message.as_bytes(),
                self.previous_digest,
            )
    }

    pub fn digest(&self) -> AuditDigest {
        self.digest
    }

    pub fn previous_digest(&self) -> AuditDigest {
        self.previous_digest
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditChain {
    instance_id: InstanceId,
    records: Vec<AuditRecord>,
}

impl AuditChain {
    pub fn new(instance_id: InstanceId) -> Self {
        Self {
            instance_id,
            records: Vec::new(),
        }
    }

    pub fn append(
        &mut self,
        role_id: Option<RoleId>,
        kind: AuditEventKind,
        message: impl Into<String>,
    ) -> Result<AuditRecord> {
        let sequence = self.records.len() as u64 + 1;
        let previous_digest = self
            .records
            .last()
            .map_or(AuditDigest::zero(), AuditRecord::digest);
        let record = AuditRecord::new(
            self.instance_id,
            role_id,
            sequence,
            kind,
            message,
            previous_digest,
        )?;
        self.records.push(record.clone());
        Ok(record)
    }

    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn verify(&self) -> bool {
        Self::verify_records(self.instance_id, &self.records)
    }

    pub fn verify_records(instance_id: InstanceId, records: &[AuditRecord]) -> bool {
        let mut previous_digest = AuditDigest::zero();
        for (index, record) in records.iter().enumerate() {
            if record.instance_id != instance_id {
                return false;
            }
            if record.sequence != index as u64 + 1 {
                return false;
            }
            if record.previous_digest != previous_digest {
                return false;
            }
            if !record.verify() {
                return false;
            }
            previous_digest = record.digest;
        }
        true
    }
}

fn audit_digest(
    instance_id: InstanceId,
    role_id: Option<RoleId>,
    sequence: u64,
    kind: &AuditEventKind,
    message: &[u8],
    previous_digest: AuditDigest,
) -> AuditDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"RNOVDB-AUDIT-V1");
    hasher.update(instance_id.get().to_be_bytes());
    hasher.update(role_id.map_or(0, RoleId::get).to_be_bytes());
    hasher.update(sequence.to_be_bytes());
    hasher.update([audit_kind_tag(kind)]);
    hasher.update((message.len() as u64).to_be_bytes());
    hasher.update(message);
    hasher.update(previous_digest.as_bytes());
    AuditDigest::from_bytes(hasher.finalize().into())
}

fn audit_kind_tag(kind: &AuditEventKind) -> u8 {
    match kind {
        AuditEventKind::Authentication => 0,
        AuditEventKind::Authorization => 1,
        AuditEventKind::PrivilegeChange => 2,
        AuditEventKind::PolicyChange => 3,
        AuditEventKind::KeyEvent => 4,
        AuditEventKind::Ddl => 5,
        AuditEventKind::BackupRestore => 6,
        AuditEventKind::DeniedAccess => 7,
    }
}
