use std::collections::{BTreeMap, BTreeSet};

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use rnmdb_common::{
    ErrorKind, Result, RnovError,
    ids::{InstanceId, RelationId, RoleId},
};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

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
    Decrypt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPrincipal {
    username: String,
    role_id: Option<RoleId>,
}

impl AuthenticatedPrincipal {
    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn role_id(&self) -> Option<RoleId> {
        self.role_id
    }
}

pub trait AuthenticationProvider {
    fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<AuthenticatedPrincipal>>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalCredential {
    username: String,
    password_hash: String,
    role_id: Option<RoleId>,
    enabled: bool,
}

impl LocalCredential {
    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password_hash(&self) -> &str {
        &self.password_hash
    }

    pub fn role_id(&self) -> Option<RoleId> {
        self.role_id
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LocalCredentialStore {
    credentials: std::collections::BTreeMap<String, LocalCredential>,
}

impl LocalCredentialStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_user(
        &mut self,
        username: impl Into<String>,
        password: &str,
        role_id: Option<RoleId>,
    ) -> Result<()> {
        let username = username.into();
        validate_username(&username)?;
        validate_password(password)?;
        if self.credentials.contains_key(&username) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("user already exists: {username}"),
            ));
        }

        let password_hash = hash_password(password)?;
        self.credentials.insert(
            username.clone(),
            LocalCredential {
                username,
                password_hash,
                role_id,
                enabled: true,
            },
        );
        Ok(())
    }

    pub fn credential(&self, username: &str) -> Option<&LocalCredential> {
        self.credentials.get(username)
    }

    pub fn credentials(&self) -> impl Iterator<Item = &LocalCredential> {
        self.credentials.values()
    }

    pub fn disable_user(&mut self, username: &str) -> bool {
        self.set_user_enabled(username, false)
    }

    pub fn enable_user(&mut self, username: &str) -> bool {
        self.set_user_enabled(username, true)
    }

    fn set_user_enabled(&mut self, username: &str, enabled: bool) -> bool {
        let Some(credential) = self.credentials.get_mut(username) else {
            return false;
        };
        credential.enabled = enabled;
        true
    }
}

impl AuthenticationProvider for LocalCredentialStore {
    fn authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<Option<AuthenticatedPrincipal>> {
        let Some(credential) = self.credentials.get(username) else {
            return Ok(None);
        };
        if !credential.enabled {
            return Ok(None);
        }
        if !verify_password(password, &credential.password_hash)? {
            return Ok(None);
        }

        Ok(Some(AuthenticatedPrincipal {
            username: credential.username.clone(),
            role_id: credential.role_id,
        }))
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct RelationGrant {
    role_id: RoleId,
    relation_id: RelationId,
    privilege: ObjectPrivilege,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ColumnDecryptGrant {
    role_id: RoleId,
    relation_id: RelationId,
    column_name: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DefaultPrivilegeRule {
    schema_name: String,
    role_id: RoleId,
    privilege: ObjectPrivilege,
}

impl DefaultPrivilegeRule {
    pub fn new(
        schema_name: impl Into<String>,
        role_id: RoleId,
        privilege: ObjectPrivilege,
    ) -> Result<Self> {
        let schema_name = schema_name.into();
        validate_schema_name(&schema_name)?;
        Ok(Self {
            schema_name,
            role_id,
            privilege,
        })
    }

    pub fn schema_name(&self) -> &str {
        &self.schema_name
    }

    pub fn role_id(&self) -> RoleId {
        self.role_id
    }

    pub fn privilege(&self) -> ObjectPrivilege {
        self.privilege
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccessControl {
    relation_grants: BTreeSet<RelationGrant>,
    default_relation_privileges: BTreeSet<DefaultPrivilegeRule>,
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

    pub fn add_default_relation_privilege(
        &mut self,
        schema_name: impl Into<String>,
        role_id: RoleId,
        privilege: ObjectPrivilege,
    ) -> bool {
        let Ok(rule) = DefaultPrivilegeRule::new(schema_name, role_id, privilege) else {
            return false;
        };
        self.default_relation_privileges.insert(rule)
    }

    pub fn revoke_default_relation_privilege(
        &mut self,
        schema_name: impl Into<String>,
        role_id: RoleId,
        privilege: ObjectPrivilege,
    ) -> bool {
        let Ok(rule) = DefaultPrivilegeRule::new(schema_name, role_id, privilege) else {
            return false;
        };
        self.default_relation_privileges.remove(&rule)
    }

    pub fn default_relation_privileges(&self, schema_name: &str) -> Vec<DefaultPrivilegeRule> {
        self.default_relation_privileges
            .iter()
            .filter(|rule| rule.schema_name == schema_name)
            .cloned()
            .collect()
    }

    pub fn apply_default_relation_privileges(
        &mut self,
        schema_name: &str,
        relation_id: RelationId,
        owner_role_id: RoleId,
    ) -> Result<Vec<DefaultPrivilegeRule>> {
        validate_schema_name(schema_name)?;
        grant_relation_owner_privileges(self, owner_role_id, relation_id);

        let rules = self.default_relation_privileges(schema_name);
        for rule in &rules {
            self.grant_relation_privilege(rule.role_id, relation_id, rule.privilege);
        }
        Ok(rules)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ColumnKeyId(u64);

impl ColumnKeyId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for ColumnKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "colkey:{}", self.0)
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ColumnKeyMaterial([u8; 32]);

impl ColumnKeyMaterial {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    const fn as_bytes(self) -> [u8; 32] {
        self.0
    }

    fn to_key(self) -> Key {
        Key::try_from(&self.0[..]).expect("ColumnKeyMaterial is always 32 bytes")
    }
}

impl std::fmt::Debug for ColumnKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ColumnKeyMaterial")
            .field(&"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WrappedColumnKey {
    key_id: ColumnKeyId,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
    authentication_tag: [u8; 32],
}

impl WrappedColumnKey {
    pub fn key_id(&self) -> ColumnKeyId {
        self.key_id
    }

    pub fn nonce(&self) -> [u8; 12] {
        self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    pub fn authentication_tag(&self) -> [u8; 32] {
        self.authentication_tag
    }

    pub fn verify_authentication_tag(&self, key_encryption_key: &ColumnKeyMaterial) -> bool {
        wrapped_key_authentication_tag(
            key_encryption_key,
            self.key_id,
            &self.nonce,
            &self.ciphertext,
        ) == self.authentication_tag
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColumnEncryptionMetadata {
    instance_id: InstanceId,
    relation_id: RelationId,
    column_name: String,
    version: u64,
    active_key_id: ColumnKeyId,
    previous_key_id: Option<ColumnKeyId>,
    created_by: RoleId,
    rotated_by: Option<RoleId>,
    wrapped_key: WrappedColumnKey,
}

impl ColumnEncryptionMetadata {
    pub fn instance_id(&self) -> InstanceId {
        self.instance_id
    }

    pub fn relation_id(&self) -> RelationId {
        self.relation_id
    }

    pub fn column_name(&self) -> &str {
        &self.column_name
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn active_key_id(&self) -> ColumnKeyId {
        self.active_key_id
    }

    pub fn previous_key_id(&self) -> Option<ColumnKeyId> {
        self.previous_key_id
    }

    pub fn created_by(&self) -> RoleId {
        self.created_by
    }

    pub fn rotated_by(&self) -> Option<RoleId> {
        self.rotated_by
    }

    pub fn wrapped_key(&self) -> &WrappedColumnKey {
        &self.wrapped_key
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColumnDecryptionRequest {
    role_id: RoleId,
    relation_id: RelationId,
    column_name: String,
}

impl ColumnDecryptionRequest {
    pub fn new(role_id: RoleId, relation_id: RelationId, column_name: impl Into<String>) -> Self {
        Self {
            role_id,
            relation_id,
            column_name: column_name.into(),
        }
    }

    pub fn role_id(&self) -> RoleId {
        self.role_id
    }

    pub fn relation_id(&self) -> RelationId {
        self.relation_id
    }

    pub fn column_name(&self) -> &str {
        &self.column_name
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColumnEncryptionCatalog {
    instance_id: InstanceId,
    access: AccessControl,
    metadata: BTreeMap<ColumnRef, ColumnEncryptionMetadata>,
    column_decrypt_grants: BTreeSet<ColumnDecryptGrant>,
    next_key_id: u64,
}

impl ColumnEncryptionCatalog {
    pub fn new(instance_id: InstanceId) -> Self {
        Self {
            instance_id,
            access: AccessControl::new(),
            metadata: BTreeMap::new(),
            column_decrypt_grants: BTreeSet::new(),
            next_key_id: 1,
        }
    }

    pub fn instance_id(&self) -> InstanceId {
        self.instance_id
    }

    pub fn create_column_key(
        &mut self,
        relation_id: RelationId,
        column_name: impl Into<String>,
        owner_role_id: RoleId,
        data_encryption_key: ColumnKeyMaterial,
        key_encryption_key: &ColumnKeyMaterial,
    ) -> Result<ColumnEncryptionMetadata> {
        let column_ref = ColumnRef::new(relation_id, column_name)?;
        if self.metadata.contains_key(&column_ref) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!(
                    "column encryption key already exists: {}.{}",
                    relation_id, column_ref.column_name
                ),
            ));
        }

        let key_id = self.allocate_key_id();
        let wrapped_key = wrap_column_key(
            self.instance_id,
            relation_id,
            &column_ref.column_name,
            1,
            key_id,
            data_encryption_key,
            key_encryption_key,
        )?;
        let metadata = ColumnEncryptionMetadata {
            instance_id: self.instance_id,
            relation_id,
            column_name: column_ref.column_name.clone(),
            version: 1,
            active_key_id: key_id,
            previous_key_id: None,
            created_by: owner_role_id,
            rotated_by: None,
            wrapped_key,
        };
        self.metadata.insert(column_ref, metadata.clone());
        self.column_decrypt_grants.insert(ColumnDecryptGrant {
            role_id: owner_role_id,
            relation_id,
            column_name: metadata.column_name.clone(),
        });
        Ok(metadata)
    }

    pub fn rotate_column_key(
        &mut self,
        relation_id: RelationId,
        column_name: impl Into<String>,
        rotated_by: RoleId,
        data_encryption_key: ColumnKeyMaterial,
        key_encryption_key: &ColumnKeyMaterial,
    ) -> Result<ColumnEncryptionMetadata> {
        let column_ref = ColumnRef::new(relation_id, column_name)?;
        let (version, previous_key_id) = {
            let metadata = self.column_metadata_by_ref(&column_ref)?;
            (metadata.version + 1, metadata.active_key_id)
        };
        let key_id = self.allocate_key_id();
        let wrapped_key = wrap_column_key(
            self.instance_id,
            relation_id,
            &column_ref.column_name,
            version,
            key_id,
            data_encryption_key,
            key_encryption_key,
        )?;
        let metadata = self.column_metadata_by_ref_mut(&column_ref)?;
        metadata.version = version;
        metadata.previous_key_id = Some(previous_key_id);
        metadata.active_key_id = key_id;
        metadata.rotated_by = Some(rotated_by);
        metadata.wrapped_key = wrapped_key;
        Ok(metadata.clone())
    }

    pub fn column_metadata(
        &self,
        relation_id: RelationId,
        column_name: &str,
    ) -> Option<&ColumnEncryptionMetadata> {
        let Ok(column_ref) = ColumnRef::new(relation_id, column_name) else {
            return None;
        };
        self.metadata.get(&column_ref)
    }

    pub fn metadata(&self) -> impl Iterator<Item = &ColumnEncryptionMetadata> {
        self.metadata.values()
    }

    pub fn grant_column_decrypt(
        &mut self,
        relation_id: RelationId,
        column_name: impl Into<String>,
        role_id: RoleId,
    ) -> Result<bool> {
        let column_ref = ColumnRef::new(relation_id, column_name)?;
        self.column_metadata_by_ref(&column_ref)?;
        Ok(self.column_decrypt_grants.insert(ColumnDecryptGrant {
            role_id,
            relation_id,
            column_name: column_ref.column_name,
        }))
    }

    pub fn revoke_column_decrypt(
        &mut self,
        relation_id: RelationId,
        column_name: impl Into<String>,
        role_id: RoleId,
    ) -> Result<bool> {
        let column_ref = ColumnRef::new(relation_id, column_name)?;
        self.column_metadata_by_ref(&column_ref)?;
        Ok(self.column_decrypt_grants.remove(&ColumnDecryptGrant {
            role_id,
            relation_id,
            column_name: column_ref.column_name,
        }))
    }

    pub fn grant_relation_privilege(
        &mut self,
        role_id: RoleId,
        relation_id: RelationId,
        privilege: ObjectPrivilege,
    ) -> bool {
        if privilege == ObjectPrivilege::Decrypt {
            return false;
        }
        self.access
            .grant_relation_privilege(role_id, relation_id, privilege)
    }

    pub fn authorize_decrypt(&self, request: ColumnDecryptionRequest) -> bool {
        let Ok(column_ref) = ColumnRef::new(request.relation_id, request.column_name) else {
            return false;
        };
        self.metadata.contains_key(&column_ref)
            && self.column_decrypt_grants.contains(&ColumnDecryptGrant {
                role_id: request.role_id,
                relation_id: request.relation_id,
                column_name: column_ref.column_name,
            })
    }

    pub fn unwrap_column_key(
        &self,
        relation_id: RelationId,
        column_name: &str,
        role_id: RoleId,
        key_encryption_key: &ColumnKeyMaterial,
    ) -> Result<ColumnKeyMaterial> {
        let column_ref = ColumnRef::new(relation_id, column_name)?;
        if !self.authorize_decrypt(ColumnDecryptionRequest::new(
            role_id,
            relation_id,
            column_ref.column_name.as_str(),
        )) {
            return Err(RnovError::new(
                ErrorKind::Security,
                format!(
                    "role {role_id} is not authorized to decrypt column {relation_id}.{column_name}"
                ),
            ));
        }

        let metadata = self.column_metadata_by_ref(&column_ref)?;
        unwrap_column_key(metadata, key_encryption_key)
    }

    fn allocate_key_id(&mut self) -> ColumnKeyId {
        let key_id = ColumnKeyId::new(self.next_key_id);
        self.next_key_id += 1;
        key_id
    }

    fn column_metadata_by_ref(&self, column_ref: &ColumnRef) -> Result<&ColumnEncryptionMetadata> {
        self.metadata.get(column_ref).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!(
                    "column encryption metadata not found: {}.{}",
                    column_ref.relation_id, column_ref.column_name
                ),
            )
        })
    }

    fn column_metadata_by_ref_mut(
        &mut self,
        column_ref: &ColumnRef,
    ) -> Result<&mut ColumnEncryptionMetadata> {
        self.metadata.get_mut(column_ref).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!(
                    "column encryption metadata not found: {}.{}",
                    column_ref.relation_id, column_ref.column_name
                ),
            )
        })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ColumnRef {
    relation_id: RelationId,
    column_name: String,
}

impl ColumnRef {
    fn new(relation_id: RelationId, column_name: impl Into<String>) -> Result<Self> {
        let column_name = column_name.into();
        validate_column_name(&column_name)?;
        Ok(Self {
            relation_id,
            column_name,
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

    pub fn from_stored_parts(
        instance_id: InstanceId,
        role_id: Option<RoleId>,
        sequence: u64,
        kind: AuditEventKind,
        message: impl Into<String>,
        previous_digest: AuditDigest,
        digest: AuditDigest,
    ) -> Result<Self> {
        let message = message.into();
        if message.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "audit message cannot be empty",
            ));
        }
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

    pub fn instance_id(&self) -> InstanceId {
        self.instance_id
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
        self.inspect().is_valid()
    }

    pub fn verify_records(instance_id: InstanceId, records: &[AuditRecord]) -> bool {
        Self::inspect_records(instance_id, records).is_valid()
    }

    pub fn inspect(&self) -> AuditInspection {
        Self::inspect_records(self.instance_id, &self.records)
    }

    pub fn inspect_records(instance_id: InstanceId, records: &[AuditRecord]) -> AuditInspection {
        let mut previous_digest = AuditDigest::zero();
        for (index, record) in records.iter().enumerate() {
            if record.instance_id != instance_id {
                return AuditInspection::invalid(
                    instance_id,
                    records.len(),
                    previous_digest,
                    AuditInspectionFailure::InstanceMismatch {
                        record_index: index,
                        expected: instance_id,
                        actual: record.instance_id,
                    },
                );
            }
            let expected_sequence = index as u64 + 1;
            if record.sequence != expected_sequence {
                return AuditInspection::invalid(
                    instance_id,
                    records.len(),
                    previous_digest,
                    AuditInspectionFailure::SequenceGap {
                        record_index: index,
                        expected: expected_sequence,
                        actual: record.sequence,
                    },
                );
            }
            if record.previous_digest != previous_digest {
                return AuditInspection::invalid(
                    instance_id,
                    records.len(),
                    previous_digest,
                    AuditInspectionFailure::PreviousDigestMismatch {
                        record_index: index,
                        expected: previous_digest,
                        actual: record.previous_digest,
                    },
                );
            }
            if !record.verify() {
                return AuditInspection::invalid(
                    instance_id,
                    records.len(),
                    previous_digest,
                    AuditInspectionFailure::RecordDigestMismatch {
                        record_index: index,
                        sequence: record.sequence,
                    },
                );
            }
            previous_digest = record.digest;
        }
        AuditInspection::valid(instance_id, records.len(), previous_digest)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditInspection {
    instance_id: InstanceId,
    record_count: usize,
    valid: bool,
    last_valid_digest: AuditDigest,
    failure: Option<AuditInspectionFailure>,
}

impl AuditInspection {
    fn valid(instance_id: InstanceId, record_count: usize, last_valid_digest: AuditDigest) -> Self {
        Self {
            instance_id,
            record_count,
            valid: true,
            last_valid_digest,
            failure: None,
        }
    }

    fn invalid(
        instance_id: InstanceId,
        record_count: usize,
        last_valid_digest: AuditDigest,
        failure: AuditInspectionFailure,
    ) -> Self {
        Self {
            instance_id,
            record_count,
            valid: false,
            last_valid_digest,
            failure: Some(failure),
        }
    }

    pub fn instance_id(&self) -> InstanceId {
        self.instance_id
    }

    pub fn record_count(&self) -> usize {
        self.record_count
    }

    pub fn is_valid(&self) -> bool {
        self.valid
    }

    pub fn last_valid_digest(&self) -> AuditDigest {
        self.last_valid_digest
    }

    pub fn failure(&self) -> Option<&AuditInspectionFailure> {
        self.failure.as_ref()
    }

    pub fn to_text_report(&self) -> String {
        let mut lines = vec![
            format!("instance: {}", self.instance_id),
            format!("valid: {}", self.valid),
            format!("record_count: {}", self.record_count),
            format!("last_valid_digest: {}", self.last_valid_digest.to_hex()),
        ];

        match &self.failure {
            Some(failure) => failure.push_report_lines(&mut lines),
            None => lines.push("failure: none".to_string()),
        }

        lines.join("\n")
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditInspectionFailure {
    InstanceMismatch {
        record_index: usize,
        expected: InstanceId,
        actual: InstanceId,
    },
    SequenceGap {
        record_index: usize,
        expected: u64,
        actual: u64,
    },
    PreviousDigestMismatch {
        record_index: usize,
        expected: AuditDigest,
        actual: AuditDigest,
    },
    RecordDigestMismatch {
        record_index: usize,
        sequence: u64,
    },
}

impl AuditInspectionFailure {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::InstanceMismatch { .. } => "instance_mismatch",
            Self::SequenceGap { .. } => "sequence_gap",
            Self::PreviousDigestMismatch { .. } => "previous_digest_mismatch",
            Self::RecordDigestMismatch { .. } => "record_digest_mismatch",
        }
    }

    pub fn record_index(&self) -> usize {
        match self {
            Self::InstanceMismatch { record_index, .. }
            | Self::SequenceGap { record_index, .. }
            | Self::PreviousDigestMismatch { record_index, .. }
            | Self::RecordDigestMismatch { record_index, .. } => *record_index,
        }
    }

    fn push_report_lines(&self, lines: &mut Vec<String>) {
        lines.push(format!("failure: {}", self.kind()));
        lines.push(format!("failure_record_index: {}", self.record_index()));

        match self {
            Self::InstanceMismatch {
                expected, actual, ..
            } => {
                lines.push(format!("expected_instance: {expected}"));
                lines.push(format!("actual_instance: {actual}"));
            }
            Self::SequenceGap {
                expected, actual, ..
            } => {
                lines.push(format!("expected_sequence: {expected}"));
                lines.push(format!("actual_sequence: {actual}"));
            }
            Self::PreviousDigestMismatch {
                expected, actual, ..
            } => {
                lines.push(format!("expected_previous_digest: {}", expected.to_hex()));
                lines.push(format!("actual_previous_digest: {}", actual.to_hex()));
            }
            Self::RecordDigestMismatch { sequence, .. } => {
                lines.push(format!("sequence: {sequence}"));
            }
        }
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

fn validate_username(username: &str) -> Result<()> {
    if username.trim().is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "user name cannot be empty",
        ));
    }
    Ok(())
}

fn validate_password(password: &str) -> Result<()> {
    if password.is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "password cannot be empty",
        ));
    }
    Ok(())
}

fn validate_schema_name(schema_name: &str) -> Result<()> {
    if schema_name.trim().is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "schema name cannot be empty",
        ));
    }
    Ok(())
}

fn validate_column_name(column_name: &str) -> Result<()> {
    if column_name.trim().is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "column name cannot be empty",
        ));
    }
    Ok(())
}

fn grant_relation_owner_privileges(
    access: &mut AccessControl,
    owner_role_id: RoleId,
    relation_id: RelationId,
) {
    for privilege in relation_owner_privileges() {
        access.grant_relation_privilege(owner_role_id, relation_id, privilege);
    }
}

fn relation_owner_privileges() -> [ObjectPrivilege; 4] {
    [
        ObjectPrivilege::Select,
        ObjectPrivilege::Insert,
        ObjectPrivilege::Update,
        ObjectPrivilege::Delete,
    ]
}

fn wrap_column_key(
    instance_id: InstanceId,
    relation_id: RelationId,
    column_name: &str,
    version: u64,
    key_id: ColumnKeyId,
    data_encryption_key: ColumnKeyMaterial,
    key_encryption_key: &ColumnKeyMaterial,
) -> Result<WrappedColumnKey> {
    let nonce = column_key_nonce(instance_id, relation_id, version, key_id);
    let aad = column_key_associated_data(instance_id, relation_id, column_name, version, key_id);
    let key = key_encryption_key.to_key();
    let nonce_value = Nonce::try_from(&nonce[..]).expect("column key nonce is always 12 bytes");
    let cipher = ChaCha20Poly1305::new(&key);
    let ciphertext = cipher
        .encrypt(
            &nonce_value,
            Payload {
                msg: &data_encryption_key.as_bytes(),
                aad: &aad,
            },
        )
        .map_err(|_| RnovError::new(ErrorKind::Security, "column key wrapping failed"))?;
    let authentication_tag =
        wrapped_key_authentication_tag(key_encryption_key, key_id, &nonce, &ciphertext);
    Ok(WrappedColumnKey {
        key_id,
        nonce,
        ciphertext,
        authentication_tag,
    })
}

fn unwrap_column_key(
    metadata: &ColumnEncryptionMetadata,
    key_encryption_key: &ColumnKeyMaterial,
) -> Result<ColumnKeyMaterial> {
    if !metadata
        .wrapped_key
        .verify_authentication_tag(key_encryption_key)
    {
        return Err(RnovError::new(
            ErrorKind::Security,
            "column key authentication failed",
        ));
    }

    let aad = column_key_associated_data(
        metadata.instance_id,
        metadata.relation_id,
        &metadata.column_name,
        metadata.version,
        metadata.active_key_id,
    );
    let key = key_encryption_key.to_key();
    let nonce = Nonce::try_from(&metadata.wrapped_key.nonce[..])
        .expect("column key nonce is always 12 bytes");
    let cipher = ChaCha20Poly1305::new(&key);
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &metadata.wrapped_key.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| {
            RnovError::new(
                ErrorKind::Security,
                "column key authentication failed during unwrap",
            )
        })?;
    let bytes: [u8; 32] = plaintext.try_into().map_err(|_| {
        RnovError::new(
            ErrorKind::Corruption,
            "column key plaintext length is invalid",
        )
    })?;
    Ok(ColumnKeyMaterial::from_bytes(bytes))
}

fn column_key_nonce(
    instance_id: InstanceId,
    relation_id: RelationId,
    version: u64,
    key_id: ColumnKeyId,
) -> [u8; 12] {
    let digest = column_key_nonce_digest(instance_id, relation_id, version, key_id);
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&digest[..12]);
    nonce
}

fn column_key_nonce_digest(
    instance_id: InstanceId,
    relation_id: RelationId,
    version: u64,
    key_id: ColumnKeyId,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"RNOVDB-COLUMN-KEY-NONCE-V1");
    hasher.update(instance_id.get().to_be_bytes());
    hasher.update(relation_id.get().to_be_bytes());
    hasher.update(version.to_be_bytes());
    hasher.update(key_id.get().to_be_bytes());
    hasher.finalize().into()
}

fn column_key_associated_data(
    instance_id: InstanceId,
    relation_id: RelationId,
    column_name: &str,
    version: u64,
    key_id: ColumnKeyId,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64 + column_name.len());
    aad.extend_from_slice(b"RNOVDB-COLUMN-KEY-WRAP-V1");
    aad.extend_from_slice(&instance_id.get().to_be_bytes());
    aad.extend_from_slice(&relation_id.get().to_be_bytes());
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(&key_id.get().to_be_bytes());
    aad.extend_from_slice(&(column_name.len() as u64).to_be_bytes());
    aad.extend_from_slice(column_name.as_bytes());
    aad
}

fn wrapped_key_authentication_tag(
    key_encryption_key: &ColumnKeyMaterial,
    key_id: ColumnKeyId,
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(&key_encryption_key.as_bytes())
        .expect("HMAC-SHA256 accepts 32-byte column key material");
    mac.update(b"RNOVDB-COLUMN-KEY-AUTH-V1");
    mac.update(&key_id.get().to_be_bytes());
    mac.update(nonce);
    mac.update(&(ciphertext.len() as u64).to_be_bytes());
    mac.update(ciphertext);
    mac.finalize().into_bytes().into()
}

fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(password_hash_error)
}

fn verify_password(password: &str, password_hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(password_hash).map_err(password_hash_error)?;
    match Argon2::default().verify_password(password.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(error) => Err(password_hash_error(error)),
    }
}

fn password_hash_error(error: argon2::password_hash::Error) -> RnovError {
    RnovError::new(
        ErrorKind::InvalidInput,
        format!("credential password hash error: {error}"),
    )
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
