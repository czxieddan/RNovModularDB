use std::{collections::BTreeMap, fmt};

use rnmdb_common::{
    error::{ErrorKind, Result, RnovError},
    ids::{DatabaseId, FunctionId, OperatorId, PolicyId, RelationId, RoleId},
};
use rnmdb_types::SqlType;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Column {
    name: String,
    data_type: SqlType,
    nullable: bool,
    encrypted: bool,
    generated_expr: Option<String>,
    generated_stored: bool,
}

impl Column {
    pub fn new(name: impl Into<String>, data_type: SqlType) -> Self {
        Self {
            name: name.into(),
            data_type,
            nullable: true,
            encrypted: false,
            generated_expr: None,
            generated_stored: false,
        }
    }

    pub fn not_null(mut self) -> Self {
        self.nullable = false;
        self
    }

    pub fn encrypted(mut self) -> Self {
        self.encrypted = true;
        self
    }

    pub fn generated(mut self, expr: impl Into<String>, stored: bool) -> Self {
        self.generated_expr = Some(expr.into());
        self.generated_stored = stored;
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn data_type(&self) -> &SqlType {
        &self.data_type
    }

    pub fn nullable(&self) -> bool {
        self.nullable
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    pub fn generated_expr(&self) -> Option<&str> {
        self.generated_expr.as_deref()
    }

    pub fn generated_stored(&self) -> bool {
        self.generated_stored
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndexMethod {
    BTree,
    Hash,
    Gin,
    Gist,
    Brin,
}

impl IndexMethod {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BTree => "btree",
            Self::Hash => "hash",
            Self::Gin => "gin",
            Self::Gist => "gist",
            Self::Brin => "brin",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexKey {
    Column(String),
    Expression(String),
}

impl IndexKey {
    pub fn column(name: impl Into<String>) -> Self {
        Self::Column(name.into())
    }

    pub fn expression(expr: impl Into<String>) -> Self {
        Self::Expression(expr.into())
    }

    pub fn as_column(&self) -> Option<&str> {
        match self {
            Self::Column(name) => Some(name),
            Self::Expression(_) => None,
        }
    }

    pub fn as_expression(&self) -> Option<&str> {
        match self {
            Self::Column(_) => None,
            Self::Expression(expr) => Some(expr),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Table {
    relation_id: RelationId,
    schema_name: String,
    name: String,
    columns: Vec<Column>,
    version: u64,
    owner_role_id: Option<RoleId>,
}

impl Table {
    pub fn relation_id(&self) -> RelationId {
        self.relation_id
    }

    pub fn schema_name(&self) -> &str {
        &self.schema_name
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn owner_role_id(&self) -> Option<RoleId> {
        self.owner_role_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Schema {
    name: String,
    tables: BTreeMap<String, Table>,
}

impl Schema {
    pub fn name(&self) -> &str {
        &self.name
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Catalog {
    database_id: DatabaseId,
    next_relation_id: u64,
    next_function_id: u64,
    next_operator_id: u64,
    next_role_id: u64,
    next_policy_id: u64,
    schemas: BTreeMap<String, Schema>,
    functions: Vec<Function>,
    procedures: Vec<Procedure>,
    operators: Vec<Operator>,
    indexes: Vec<Index>,
    roles: BTreeMap<String, Role>,
    grants: Vec<TableGrant>,
    procedure_grants: Vec<ProcedureGrant>,
    row_policies: BTreeMap<RelationId, Vec<RowPolicy>>,
    row_security: BTreeMap<RelationId, RowSecurityMode>,
}

impl Catalog {
    pub fn new(database_id: DatabaseId) -> Self {
        Self {
            database_id,
            next_relation_id: 1,
            next_function_id: 1,
            next_operator_id: 1,
            next_role_id: 1,
            next_policy_id: 1,
            schemas: BTreeMap::new(),
            functions: Vec::new(),
            procedures: Vec::new(),
            operators: Vec::new(),
            indexes: Vec::new(),
            roles: BTreeMap::new(),
            grants: Vec::new(),
            procedure_grants: Vec::new(),
            row_policies: BTreeMap::new(),
            row_security: BTreeMap::new(),
        }
    }

    pub fn database_id(&self) -> DatabaseId {
        self.database_id
    }

    pub fn functions(&self) -> &[Function] {
        &self.functions
    }

    pub fn procedures(&self) -> &[Procedure] {
        &self.procedures
    }

    pub fn get_function(&self, name: &str, argument_types: &[SqlType]) -> Option<&Function> {
        self.functions
            .iter()
            .find(|function| function.name == name && function.argument_types == argument_types)
    }

    pub fn get_procedure(&self, name: &str, argument_types: &[SqlType]) -> Option<&Procedure> {
        self.procedures
            .iter()
            .find(|procedure| procedure.name == name && procedure.argument_types == argument_types)
    }

    pub fn procedure_by_id(&self, procedure_id: FunctionId) -> Option<&Procedure> {
        self.procedures
            .iter()
            .find(|procedure| procedure.procedure_id == procedure_id)
    }

    pub fn drop_function(
        &mut self,
        name: &str,
        argument_types: &[SqlType],
    ) -> Result<Option<Function>> {
        validate_identifier("function", name)?;
        let Some(position) = self.functions.iter().position(|function| {
            function.name == name && function.argument_types == argument_types
        }) else {
            return Ok(None);
        };
        let function_id = self.functions[position].function_id;
        if self
            .operators
            .iter()
            .any(|operator| operator.signature.function_id == function_id)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("function is still used by operator: {name}"),
            ));
        }
        Ok(Some(self.functions.remove(position)))
    }

    pub fn drop_procedure(
        &mut self,
        name: &str,
        argument_types: &[SqlType],
    ) -> Result<Option<Procedure>> {
        validate_identifier("procedure", name)?;
        let Some(position) = self.procedures.iter().position(|procedure| {
            procedure.name == name && procedure.argument_types == argument_types
        }) else {
            return Ok(None);
        };
        let procedure = self.procedures.remove(position);
        self.procedure_grants
            .retain(|grant| grant.procedure_id != procedure.procedure_id);
        Ok(Some(procedure))
    }

    pub fn operators(&self) -> &[Operator] {
        &self.operators
    }

    pub fn get_operator(
        &self,
        symbol: &str,
        left_type: &SqlType,
        right_type: &SqlType,
    ) -> Option<&Operator> {
        self.operators.iter().find(|operator| {
            operator.signature.symbol == symbol
                && operator.signature.left_type == *left_type
                && operator.signature.right_type == *right_type
        })
    }

    pub fn drop_operator(
        &mut self,
        symbol: &str,
        left_type: &SqlType,
        right_type: &SqlType,
    ) -> Result<Option<Operator>> {
        validate_identifier("operator", symbol)?;
        let Some(position) = self.operators.iter().position(|operator| {
            operator.signature.symbol == symbol
                && operator.signature.left_type == *left_type
                && operator.signature.right_type == *right_type
        }) else {
            return Ok(None);
        };
        Ok(Some(self.operators.remove(position)))
    }

    pub fn indexes(&self) -> &[Index] {
        &self.indexes
    }

    pub fn get_index(&self, schema_name: &str, index_name: &str) -> Option<&Index> {
        self.indexes
            .iter()
            .find(|index| index.schema_name == schema_name && index.name == index_name)
    }

    pub fn drop_index(&mut self, schema_name: &str, index_name: &str) -> Result<Option<Index>> {
        validate_identifier("index", index_name)?;
        if !self.schemas.contains_key(schema_name) {
            return Err(RnovError::new(
                ErrorKind::NotFound,
                format!("schema does not exist: {schema_name}"),
            ));
        }
        let Some(position) = self
            .indexes
            .iter()
            .position(|index| index.schema_name == schema_name && index.name == index_name)
        else {
            return Ok(None);
        };
        Ok(Some(self.indexes.remove(position)))
    }

    pub fn get_role(&self, name: &str) -> Option<&Role> {
        self.roles.get(name)
    }

    pub fn drop_role(&mut self, name: &str) -> Result<Option<Role>> {
        validate_identifier("role", name)?;
        let Some(role) = self.roles.remove(name) else {
            return Ok(None);
        };
        self.grants.retain(|grant| grant.role_id != role.role_id);
        self.procedure_grants
            .retain(|grant| grant.role_id != role.role_id);
        for schema in self.schemas.values_mut() {
            for table in schema.tables.values_mut() {
                if table.owner_role_id == Some(role.role_id) {
                    table.owner_role_id = None;
                    table.version += 1;
                }
            }
        }
        Ok(Some(role))
    }

    pub fn create_schema(&mut self, name: impl Into<String>) -> Result<&Schema> {
        let name = name.into();
        validate_identifier("schema", &name)?;
        if self.schemas.contains_key(&name) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("schema already exists: {name}"),
            ));
        }

        self.schemas.insert(
            name.clone(),
            Schema {
                name: name.clone(),
                tables: BTreeMap::new(),
            },
        );
        Ok(self.schemas.get(&name).expect("schema inserted"))
    }

    pub fn create_table(
        &mut self,
        schema_name: &str,
        table_name: impl Into<String>,
        columns: Vec<Column>,
    ) -> Result<&Table> {
        let table_name = table_name.into();
        validate_identifier("table", &table_name)?;
        validate_columns(&columns)?;

        let schema = self.schemas.get_mut(schema_name).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("schema does not exist: {schema_name}"),
            )
        })?;

        if schema.tables.contains_key(&table_name) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("table already exists: {schema_name}.{table_name}"),
            ));
        }

        let relation_id = RelationId::new(self.next_relation_id);
        self.next_relation_id += 1;
        schema.tables.insert(
            table_name.clone(),
            Table {
                relation_id,
                schema_name: schema_name.to_string(),
                name: table_name.clone(),
                columns,
                version: 1,
                owner_role_id: None,
            },
        );
        Ok(schema.tables.get(&table_name).expect("table inserted"))
    }

    pub fn get_table(&self, schema_name: &str, table_name: &str) -> Option<&Table> {
        self.schemas.get(schema_name)?.tables.get(table_name)
    }

    pub fn tables(&self) -> Vec<&Table> {
        self.schemas
            .values()
            .flat_map(|schema| schema.tables.values())
            .collect()
    }

    pub fn drop_table(&mut self, schema_name: &str, table_name: &str) -> Result<Option<Table>> {
        let schema = self.schemas.get_mut(schema_name).ok_or_else(|| {
            RnovError::new(
                ErrorKind::NotFound,
                format!("schema does not exist: {schema_name}"),
            )
        })?;
        let Some(table) = schema.tables.remove(table_name) else {
            return Ok(None);
        };

        self.indexes
            .retain(|index| index.relation_id != table.relation_id);
        self.grants
            .retain(|grant| grant.relation_id != table.relation_id);
        self.row_policies.remove(&table.relation_id);
        self.row_security.remove(&table.relation_id);
        Ok(Some(table))
    }

    pub fn add_column(
        &mut self,
        schema_name: &str,
        table_name: &str,
        column: Column,
    ) -> Result<&Table> {
        validate_columns(std::slice::from_ref(&column))?;
        let table = self
            .schemas
            .get_mut(schema_name)
            .and_then(|schema| schema.tables.get_mut(table_name))
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::NotFound,
                    format!("table does not exist: {schema_name}.{table_name}"),
                )
            })?;

        if table
            .columns
            .iter()
            .any(|existing| existing.name == column.name)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("column already exists: {}", column.name),
            ));
        }

        table.columns.push(column);
        table.version += 1;
        Ok(table)
    }

    pub fn set_column_encrypted(
        &mut self,
        schema_name: &str,
        table_name: &str,
        column_name: &str,
        encrypted: bool,
    ) -> Result<&Table> {
        validate_identifier("column", column_name)?;
        let table = self
            .schemas
            .get_mut(schema_name)
            .and_then(|schema| schema.tables.get_mut(table_name))
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::NotFound,
                    format!("table does not exist: {schema_name}.{table_name}"),
                )
            })?;
        let column = table
            .columns
            .iter_mut()
            .find(|column| column.name.eq_ignore_ascii_case(column_name))
            .ok_or_else(|| {
                RnovError::new(
                    ErrorKind::NotFound,
                    format!("column does not exist: {column_name}"),
                )
            })?;
        if column.encrypted != encrypted {
            column.encrypted = encrypted;
            table.version += 1;
        }
        Ok(table)
    }

    pub fn register_function(
        &mut self,
        name: impl Into<String>,
        argument_types: Vec<SqlType>,
        return_type: SqlType,
    ) -> Result<Function> {
        let name = name.into();
        validate_identifier("function", &name)?;
        if self
            .functions
            .iter()
            .any(|function| function.name == name && function.argument_types == argument_types)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("function already exists: {name}"),
            ));
        }

        let function = Function {
            function_id: FunctionId::new(self.next_function_id),
            name,
            argument_types,
            return_type,
        };
        self.next_function_id += 1;
        self.functions.push(function.clone());
        Ok(function)
    }

    pub fn register_procedure(
        &mut self,
        name: impl Into<String>,
        argument_types: Vec<SqlType>,
        body: impl Into<String>,
    ) -> Result<Procedure> {
        let name = name.into();
        validate_identifier("procedure", &name)?;
        if self
            .procedures
            .iter()
            .any(|procedure| procedure.name == name && procedure.argument_types == argument_types)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("procedure already exists: {name}"),
            ));
        }

        let procedure = Procedure {
            procedure_id: FunctionId::new(self.next_function_id),
            name,
            argument_types,
            body: body.into(),
        };
        self.next_function_id += 1;
        self.procedures.push(procedure.clone());
        Ok(procedure)
    }

    pub fn register_operator(&mut self, signature: OperatorSignature) -> Result<Operator> {
        validate_identifier("operator", signature.symbol())?;
        if !self
            .functions
            .iter()
            .any(|function| function.function_id == signature.function_id)
        {
            return Err(RnovError::new(
                ErrorKind::NotFound,
                "operator implementation function does not exist",
            ));
        }
        if self
            .operators
            .iter()
            .any(|operator| operator.signature == signature)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("operator already exists: {}", signature.symbol()),
            ));
        }

        let operator = Operator {
            operator_id: OperatorId::new(self.next_operator_id),
            signature,
        };
        self.next_operator_id += 1;
        self.operators.push(operator.clone());
        Ok(operator)
    }

    pub fn create_index(
        &mut self,
        schema_name: &str,
        index_name: impl Into<String>,
        relation_id: RelationId,
        columns: Vec<String>,
        unique: bool,
    ) -> Result<Index> {
        self.create_index_with_method(
            schema_name,
            index_name,
            relation_id,
            columns,
            IndexMethod::BTree,
            unique,
        )
    }

    pub fn create_index_with_method(
        &mut self,
        schema_name: &str,
        index_name: impl Into<String>,
        relation_id: RelationId,
        columns: Vec<String>,
        method: IndexMethod,
        unique: bool,
    ) -> Result<Index> {
        let keys = columns.into_iter().map(IndexKey::column).collect();
        self.create_index_with_keys(schema_name, index_name, relation_id, keys, method, unique)
    }

    pub fn create_index_with_keys(
        &mut self,
        schema_name: &str,
        index_name: impl Into<String>,
        relation_id: RelationId,
        keys: Vec<IndexKey>,
        method: IndexMethod,
        unique: bool,
    ) -> Result<Index> {
        let index_name = index_name.into();
        validate_identifier("index", &index_name)?;
        if !self.schemas.contains_key(schema_name) {
            return Err(RnovError::new(
                ErrorKind::NotFound,
                format!("schema does not exist: {schema_name}"),
            ));
        }
        if self.get_index(schema_name, &index_name).is_some() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("index already exists: {schema_name}.{index_name}"),
            ));
        }
        let table = self.table_by_relation_id(relation_id).ok_or_else(|| {
            RnovError::new(ErrorKind::NotFound, "indexed relation does not exist")
        })?;
        validate_index_keys(table, &keys, method)?;
        let columns = keys
            .iter()
            .filter_map(|key| key.as_column().map(str::to_string))
            .collect::<Vec<_>>();
        let index = Index {
            schema_name: schema_name.to_string(),
            name: index_name,
            relation_id,
            table_name: table.name.clone(),
            keys,
            columns,
            method,
            unique,
        };
        self.indexes.push(index.clone());
        Ok(index)
    }

    pub fn create_role(&mut self, name: impl Into<String>) -> Result<Role> {
        self.create_role_with_superuser(name, false)
    }

    pub fn create_superuser_role(&mut self, name: impl Into<String>) -> Result<Role> {
        self.create_role_with_superuser(name, true)
    }

    fn create_role_with_superuser(
        &mut self,
        name: impl Into<String>,
        superuser: bool,
    ) -> Result<Role> {
        let name = name.into();
        validate_identifier("role", &name)?;
        if self.roles.contains_key(&name) {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("role already exists: {name}"),
            ));
        }

        let role = Role {
            role_id: RoleId::new(self.next_role_id),
            name: name.clone(),
            superuser,
        };
        self.next_role_id += 1;
        self.roles.insert(name, role.clone());
        Ok(role)
    }

    pub fn set_table_owner(&mut self, relation_id: RelationId, role_id: RoleId) -> Result<()> {
        self.ensure_role_exists(role_id)?;
        let table = self
            .table_by_relation_id_mut(relation_id)
            .ok_or_else(|| RnovError::new(ErrorKind::NotFound, "relation does not exist"))?;
        table.owner_role_id = Some(role_id);
        table.version += 1;
        Ok(())
    }

    pub fn role_owns_relation(&self, role_id: RoleId, relation_id: RelationId) -> bool {
        self.table_by_relation_id(relation_id)
            .is_some_and(|table| table.owner_role_id == Some(role_id))
    }

    pub fn role_is_superuser(&self, role_id: RoleId) -> bool {
        self.roles
            .values()
            .any(|role| role.role_id == role_id && role.superuser)
    }

    pub fn grant_table_privilege(
        &mut self,
        role_id: RoleId,
        relation_id: RelationId,
        privilege: Privilege,
    ) -> Result<()> {
        self.ensure_role_exists(role_id)?;
        self.ensure_relation_exists(relation_id)?;
        let grant = TableGrant {
            role_id,
            relation_id,
            privilege,
        };
        if !self.grants.contains(&grant) {
            self.grants.push(grant);
        }
        Ok(())
    }

    pub fn has_table_privilege(
        &self,
        role_id: RoleId,
        relation_id: RelationId,
        privilege: Privilege,
    ) -> bool {
        self.grants.contains(&TableGrant {
            role_id,
            relation_id,
            privilege,
        })
    }

    pub fn grant_procedure_privilege(
        &mut self,
        role_id: RoleId,
        procedure_id: FunctionId,
        privilege: Privilege,
    ) -> Result<()> {
        if privilege != Privilege::Execute {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "procedures support only Execute privilege",
            ));
        }
        self.ensure_role_exists(role_id)?;
        self.ensure_procedure_exists(procedure_id)?;
        let grant = ProcedureGrant {
            role_id,
            procedure_id,
            privilege,
        };
        if !self.procedure_grants.contains(&grant) {
            self.procedure_grants.push(grant);
        }
        Ok(())
    }

    pub fn has_procedure_privilege(
        &self,
        role_id: RoleId,
        procedure_id: FunctionId,
        privilege: Privilege,
    ) -> bool {
        if privilege != Privilege::Execute {
            return false;
        }
        self.role_is_superuser(role_id)
            || self.procedure_grants.contains(&ProcedureGrant {
                role_id,
                procedure_id,
                privilege,
            })
    }

    pub fn add_row_policy(&mut self, policy: RowPolicy) -> Result<RowPolicy> {
        self.ensure_relation_exists(policy.relation_id)?;
        if policy.name.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "row policy name cannot be empty",
            ));
        }
        if policy.predicate.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "row policy predicate cannot be empty",
            ));
        }
        if self
            .row_policies(policy.relation_id)
            .iter()
            .any(|existing| existing.name == policy.name)
        {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("row policy already exists: {}", policy.name),
            ));
        }

        let mut policy = policy;
        policy.policy_id = PolicyId::new(self.next_policy_id);
        self.next_policy_id += 1;
        self.row_policies
            .entry(policy.relation_id)
            .or_default()
            .push(policy.clone());
        Ok(policy)
    }

    pub fn row_policies(&self, relation_id: RelationId) -> &[RowPolicy] {
        self.row_policies
            .get(&relation_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn get_row_policy(&self, relation_id: RelationId, name: &str) -> Option<&RowPolicy> {
        self.row_policies(relation_id)
            .iter()
            .find(|policy| policy.name == name)
    }

    pub fn drop_row_policy(
        &mut self,
        relation_id: RelationId,
        name: &str,
    ) -> Result<Option<RowPolicy>> {
        self.ensure_relation_exists(relation_id)?;
        validate_identifier("row policy", name)?;
        let Some(policies) = self.row_policies.get_mut(&relation_id) else {
            return Ok(None);
        };
        let Some(position) = policies.iter().position(|policy| policy.name == name) else {
            return Ok(None);
        };
        let policy = policies.remove(position);
        if policies.is_empty() {
            self.row_policies.remove(&relation_id);
        }
        Ok(Some(policy))
    }

    pub fn enable_row_security(
        &mut self,
        relation_id: RelationId,
        deny_by_default: bool,
    ) -> Result<()> {
        self.ensure_relation_exists(relation_id)?;
        self.row_security
            .insert(relation_id, RowSecurityMode { deny_by_default });
        Ok(())
    }

    pub fn disable_row_security(&mut self, relation_id: RelationId) -> Result<()> {
        self.ensure_relation_exists(relation_id)?;
        self.row_security.remove(&relation_id);
        Ok(())
    }

    pub fn row_security_enabled(&self, relation_id: RelationId) -> bool {
        self.row_security.contains_key(&relation_id)
    }

    pub fn row_security_deny_by_default(&self, relation_id: RelationId) -> bool {
        self.row_security
            .get(&relation_id)
            .is_some_and(|mode| mode.deny_by_default)
    }

    fn ensure_role_exists(&self, role_id: RoleId) -> Result<()> {
        if self.roles.values().any(|role| role.role_id == role_id) {
            return Ok(());
        }
        Err(RnovError::new(ErrorKind::NotFound, "role does not exist"))
    }

    fn ensure_relation_exists(&self, relation_id: RelationId) -> Result<()> {
        if self.table_by_relation_id(relation_id).is_some() {
            return Ok(());
        }
        Err(RnovError::new(
            ErrorKind::NotFound,
            "relation does not exist",
        ))
    }

    fn ensure_procedure_exists(&self, procedure_id: FunctionId) -> Result<()> {
        if self
            .procedures
            .iter()
            .any(|procedure| procedure.procedure_id == procedure_id)
        {
            return Ok(());
        }
        Err(RnovError::new(
            ErrorKind::NotFound,
            "procedure does not exist",
        ))
    }

    fn table_by_relation_id(&self, relation_id: RelationId) -> Option<&Table> {
        self.schemas
            .values()
            .flat_map(|schema| schema.tables.values())
            .find(|table| table.relation_id == relation_id)
    }

    fn table_by_relation_id_mut(&mut self, relation_id: RelationId) -> Option<&mut Table> {
        self.schemas
            .values_mut()
            .flat_map(|schema| schema.tables.values_mut())
            .find(|table| table.relation_id == relation_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Function {
    function_id: FunctionId,
    name: String,
    argument_types: Vec<SqlType>,
    return_type: SqlType,
}

impl Function {
    pub fn function_id(&self) -> FunctionId {
        self.function_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn argument_types(&self) -> &[SqlType] {
        &self.argument_types
    }

    pub fn return_type(&self) -> &SqlType {
        &self.return_type
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Procedure {
    procedure_id: FunctionId,
    name: String,
    argument_types: Vec<SqlType>,
    body: String,
}

impl Procedure {
    pub fn procedure_id(&self) -> FunctionId {
        self.procedure_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn argument_types(&self) -> &[SqlType] {
        &self.argument_types
    }

    pub fn body(&self) -> &str {
        &self.body
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperatorSignature {
    symbol: String,
    left_type: SqlType,
    right_type: SqlType,
    result_type: SqlType,
    function_id: FunctionId,
    precedence: Option<u8>,
    commutator: Option<String>,
    negator: Option<String>,
    selectivity_function_id: Option<FunctionId>,
}

impl OperatorSignature {
    pub fn new(
        symbol: impl Into<String>,
        left_type: SqlType,
        right_type: SqlType,
        result_type: SqlType,
        function_id: FunctionId,
    ) -> Self {
        Self {
            symbol: symbol.into(),
            left_type,
            right_type,
            result_type,
            function_id,
            precedence: None,
            commutator: None,
            negator: None,
            selectivity_function_id: None,
        }
    }

    pub fn with_precedence(mut self, precedence: u8) -> Self {
        self.precedence = Some(precedence);
        self
    }

    pub fn with_commutator(mut self, commutator: impl Into<String>) -> Self {
        self.commutator = Some(commutator.into());
        self
    }

    pub fn with_negator(mut self, negator: impl Into<String>) -> Self {
        self.negator = Some(negator.into());
        self
    }

    pub fn with_selectivity_function(mut self, function_id: FunctionId) -> Self {
        self.selectivity_function_id = Some(function_id);
        self
    }

    pub fn symbol(&self) -> &str {
        &self.symbol
    }

    pub fn left_type(&self) -> &SqlType {
        &self.left_type
    }

    pub fn right_type(&self) -> &SqlType {
        &self.right_type
    }

    pub fn result_type(&self) -> &SqlType {
        &self.result_type
    }

    pub fn function_id(&self) -> FunctionId {
        self.function_id
    }

    pub fn precedence(&self) -> Option<u8> {
        self.precedence
    }

    pub fn commutator(&self) -> Option<&str> {
        self.commutator.as_deref()
    }

    pub fn negator(&self) -> Option<&str> {
        self.negator.as_deref()
    }

    pub fn selectivity_function_id(&self) -> Option<FunctionId> {
        self.selectivity_function_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Operator {
    operator_id: OperatorId,
    signature: OperatorSignature,
}

impl Operator {
    pub fn operator_id(&self) -> OperatorId {
        self.operator_id
    }

    pub fn signature(&self) -> &OperatorSignature {
        &self.signature
    }

    pub fn symbol(&self) -> &str {
        self.signature.symbol()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Index {
    schema_name: String,
    name: String,
    relation_id: RelationId,
    table_name: String,
    keys: Vec<IndexKey>,
    columns: Vec<String>,
    method: IndexMethod,
    unique: bool,
}

impl Index {
    pub fn schema_name(&self) -> &str {
        &self.schema_name
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn relation_id(&self) -> RelationId {
        self.relation_id
    }

    pub fn table_name(&self) -> &str {
        &self.table_name
    }

    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    pub fn keys(&self) -> &[IndexKey] {
        &self.keys
    }

    pub fn method(&self) -> IndexMethod {
        self.method
    }

    pub fn unique(&self) -> bool {
        self.unique
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Role {
    role_id: RoleId,
    name: String,
    superuser: bool,
}

impl Role {
    pub fn role_id(&self) -> RoleId {
        self.role_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn is_superuser(&self) -> bool {
        self.superuser
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Privilege {
    Select,
    Insert,
    Update,
    Delete,
    Execute,
}

impl fmt::Display for Privilege {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Select => "SELECT",
            Self::Insert => "INSERT",
            Self::Update => "UPDATE",
            Self::Delete => "DELETE",
            Self::Execute => "EXECUTE",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TableGrant {
    role_id: RoleId,
    relation_id: RelationId,
    privilege: Privilege,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcedureGrant {
    role_id: RoleId,
    procedure_id: FunctionId,
    privilege: Privilege,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RowSecurityMode {
    deny_by_default: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RowPolicy {
    policy_id: PolicyId,
    name: String,
    relation_id: RelationId,
    predicate: String,
}

impl RowPolicy {
    pub fn new(
        name: impl Into<String>,
        relation_id: RelationId,
        predicate: impl Into<String>,
    ) -> Self {
        Self {
            policy_id: PolicyId::new(0),
            name: name.into(),
            relation_id,
            predicate: predicate.into(),
        }
    }

    pub fn policy_id(&self) -> PolicyId {
        self.policy_id
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn relation_id(&self) -> RelationId {
        self.relation_id
    }

    pub fn predicate(&self) -> &str {
        &self.predicate
    }
}

fn validate_identifier(kind: &'static str, value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("{kind} name cannot be empty"),
        ));
    }
    Ok(())
}

fn validate_columns(columns: &[Column]) -> Result<()> {
    if columns.is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "table must have at least one column",
        ));
    }

    let mut seen = BTreeMap::new();
    for column in columns {
        validate_identifier("column", column.name())?;
        if seen.insert(column.name(), ()).is_some() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                format!("duplicate column: {}", column.name()),
            ));
        }
    }
    Ok(())
}

fn validate_index_keys(table: &Table, keys: &[IndexKey], method: IndexMethod) -> Result<()> {
    if keys.is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "index must have at least one key",
        ));
    }

    let mut seen = BTreeMap::new();
    for key in keys {
        match key {
            IndexKey::Column(column) => {
                validate_identifier("index column", column)?;
                if seen.insert(format!("column:{column}"), ()).is_some() {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        format!("duplicate index column: {column}"),
                    ));
                }
                if table
                    .columns
                    .iter()
                    .all(|existing| existing.name != *column)
                {
                    return Err(RnovError::new(
                        ErrorKind::NotFound,
                        format!("index column does not exist: {column}"),
                    ));
                }
            }
            IndexKey::Expression(expr) => {
                if !matches!(method, IndexMethod::BTree | IndexMethod::Hash) {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        "expression indexes support only btree and hash methods",
                    ));
                }
                if keys.len() != 1 {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        "expression indexes support exactly one expression",
                    ));
                }
                if expr.trim().is_empty() {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        "index expression cannot be empty",
                    ));
                }
                if seen.insert(format!("expr:{expr}"), ()).is_some() {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        format!("duplicate index expression: {expr}"),
                    ));
                }
            }
        }
    }
    Ok(())
}

pub struct CatalogCodec;

impl CatalogCodec {
    const MAGIC: [u8; 8] = *b"RNOVCAT1";
    const VERSION: u16 = 10;
    const MIN_READ_VERSION: u16 = 8;

    pub fn encode(catalog: &Catalog) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&Self::MAGIC);
        write_u16(&mut out, Self::VERSION);
        write_u64(&mut out, catalog.database_id.get());
        write_u64(&mut out, catalog.next_relation_id);
        write_u64(&mut out, catalog.next_function_id);
        write_u64(&mut out, catalog.next_operator_id);
        write_u64(&mut out, catalog.next_role_id);
        write_u64(&mut out, catalog.next_policy_id);

        write_u32(&mut out, catalog.schemas.len() as u32);
        for schema in catalog.schemas.values() {
            write_string(&mut out, &schema.name)?;
            write_u32(&mut out, schema.tables.len() as u32);
            for table in schema.tables.values() {
                write_u64(&mut out, table.relation_id.get());
                write_string(&mut out, &table.schema_name)?;
                write_string(&mut out, &table.name)?;
                write_u64(&mut out, table.version);
                write_optional_role_id(&mut out, table.owner_role_id);
                write_u32(&mut out, table.columns.len() as u32);
                for column in &table.columns {
                    write_string(&mut out, &column.name)?;
                    encode_sql_type(&mut out, &column.data_type);
                    out.push(u8::from(column.nullable));
                    out.push(u8::from(column.encrypted));
                    match &column.generated_expr {
                        Some(expr) => {
                            out.push(1);
                            write_string(&mut out, expr)?;
                            out.push(u8::from(column.generated_stored));
                        }
                        None => out.push(0),
                    }
                }
            }
        }

        write_u32(&mut out, catalog.functions.len() as u32);
        for function in &catalog.functions {
            write_u64(&mut out, function.function_id.get());
            write_string(&mut out, &function.name)?;
            write_u32(&mut out, function.argument_types.len() as u32);
            for argument_type in &function.argument_types {
                encode_sql_type(&mut out, argument_type);
            }
            encode_sql_type(&mut out, &function.return_type);
        }

        write_u32(&mut out, catalog.procedures.len() as u32);
        for procedure in &catalog.procedures {
            write_u64(&mut out, procedure.procedure_id.get());
            write_string(&mut out, &procedure.name)?;
            write_u32(&mut out, procedure.argument_types.len() as u32);
            for argument_type in &procedure.argument_types {
                encode_sql_type(&mut out, argument_type);
            }
            write_string(&mut out, &procedure.body)?;
        }

        write_u32(&mut out, catalog.operators.len() as u32);
        for operator in &catalog.operators {
            write_u64(&mut out, operator.operator_id.get());
            write_string(&mut out, &operator.signature.symbol)?;
            encode_sql_type(&mut out, &operator.signature.left_type);
            encode_sql_type(&mut out, &operator.signature.right_type);
            encode_sql_type(&mut out, &operator.signature.result_type);
            write_u64(&mut out, operator.signature.function_id.get());
            match operator.signature.precedence {
                Some(precedence) => {
                    out.push(1);
                    out.push(precedence);
                }
                None => out.push(0),
            }
            write_optional_string(&mut out, operator.signature.commutator.as_deref())?;
            write_optional_string(&mut out, operator.signature.negator.as_deref())?;
            match operator.signature.selectivity_function_id {
                Some(function_id) => {
                    out.push(1);
                    write_u64(&mut out, function_id.get());
                }
                None => out.push(0),
            }
        }

        write_u32(&mut out, catalog.indexes.len() as u32);
        for index in &catalog.indexes {
            write_string(&mut out, &index.schema_name)?;
            write_string(&mut out, &index.name)?;
            write_u64(&mut out, index.relation_id.get());
            write_string(&mut out, &index.table_name)?;
            out.push(u8::from(index.unique));
            out.push(encode_index_method(index.method));
            write_u32(&mut out, index.keys.len() as u32);
            for key in &index.keys {
                match key {
                    IndexKey::Column(column) => {
                        out.push(0);
                        write_string(&mut out, column)?;
                    }
                    IndexKey::Expression(expr) => {
                        out.push(1);
                        write_string(&mut out, expr)?;
                    }
                }
            }
        }

        write_u32(&mut out, catalog.roles.len() as u32);
        for role in catalog.roles.values() {
            write_u64(&mut out, role.role_id.get());
            write_string(&mut out, &role.name)?;
            out.push(u8::from(role.superuser));
        }

        write_u32(&mut out, catalog.grants.len() as u32);
        for grant in &catalog.grants {
            write_u64(&mut out, grant.role_id.get());
            write_u64(&mut out, grant.relation_id.get());
            out.push(encode_privilege(grant.privilege));
        }

        write_u32(&mut out, catalog.procedure_grants.len() as u32);
        for grant in &catalog.procedure_grants {
            write_u64(&mut out, grant.role_id.get());
            write_u64(&mut out, grant.procedure_id.get());
            out.push(encode_privilege(grant.privilege));
        }

        let policy_count: usize = catalog.row_policies.values().map(Vec::len).sum();
        write_u32(&mut out, policy_count as u32);
        for policies in catalog.row_policies.values() {
            for policy in policies {
                write_u64(&mut out, policy.policy_id.get());
                write_string(&mut out, &policy.name)?;
                write_u64(&mut out, policy.relation_id.get());
                write_string(&mut out, &policy.predicate)?;
            }
        }

        write_u32(&mut out, catalog.row_security.len() as u32);
        for (relation_id, mode) in &catalog.row_security {
            write_u64(&mut out, relation_id.get());
            out.push(u8::from(mode.deny_by_default));
        }

        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Catalog> {
        let mut reader = CatalogReader::new(bytes);
        if reader.read_exact(8, "catalog magic")? != Self::MAGIC {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "invalid catalog magic",
            ));
        }
        let version = reader.read_u16("catalog version")?;
        if !(Self::MIN_READ_VERSION..=Self::VERSION).contains(&version) {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                format!("unsupported catalog version {version}"),
            ));
        }

        let database_id = DatabaseId::new(reader.read_u64("database id")?);
        let mut catalog = Catalog {
            database_id,
            next_relation_id: reader.read_u64("next relation id")?,
            next_function_id: reader.read_u64("next function id")?,
            next_operator_id: reader.read_u64("next operator id")?,
            next_role_id: reader.read_u64("next role id")?,
            next_policy_id: reader.read_u64("next policy id")?,
            schemas: BTreeMap::new(),
            functions: Vec::new(),
            procedures: Vec::new(),
            operators: Vec::new(),
            indexes: Vec::new(),
            roles: BTreeMap::new(),
            grants: Vec::new(),
            procedure_grants: Vec::new(),
            row_policies: BTreeMap::new(),
            row_security: BTreeMap::new(),
        };

        let schema_count = reader.read_u32("schema count")? as usize;
        for _ in 0..schema_count {
            let schema_name = reader.read_string("schema name")?;
            let table_count = reader.read_u32("table count")? as usize;
            let mut schema = Schema {
                name: schema_name.clone(),
                tables: BTreeMap::new(),
            };
            for _ in 0..table_count {
                let relation_id = RelationId::new(reader.read_u64("relation id")?);
                let table_schema = reader.read_string("table schema")?;
                let table_name = reader.read_string("table name")?;
                let table_version = reader.read_u64("table version")?;
                let owner_role_id = if version >= 10 {
                    read_optional_role_id(&mut reader, "table owner role id")?
                } else {
                    None
                };
                let column_count = reader.read_u32("column count")? as usize;
                let mut columns = Vec::with_capacity(column_count);
                for _ in 0..column_count {
                    let name = reader.read_string("column name")?;
                    let data_type = decode_sql_type(&mut reader)?;
                    let nullable = reader.read_bool("column nullable")?;
                    let encrypted = reader.read_bool("column encrypted")?;
                    let has_generated = reader.read_bool("column generated")?;
                    let (generated_expr, generated_stored) = if has_generated {
                        (
                            Some(reader.read_string("column generated expression")?),
                            reader.read_bool("column generated stored")?,
                        )
                    } else {
                        (None, false)
                    };
                    columns.push(Column {
                        name,
                        data_type,
                        nullable,
                        encrypted,
                        generated_expr,
                        generated_stored,
                    });
                }
                schema.tables.insert(
                    table_name.clone(),
                    Table {
                        relation_id,
                        schema_name: table_schema,
                        name: table_name,
                        columns,
                        version: table_version,
                        owner_role_id,
                    },
                );
            }
            catalog.schemas.insert(schema_name, schema);
        }

        let function_count = reader.read_u32("function count")? as usize;
        for _ in 0..function_count {
            let function_id = FunctionId::new(reader.read_u64("function id")?);
            let name = reader.read_string("function name")?;
            let argument_count = reader.read_u32("function argument count")? as usize;
            let mut argument_types = Vec::with_capacity(argument_count);
            for _ in 0..argument_count {
                argument_types.push(decode_sql_type(&mut reader)?);
            }
            let return_type = decode_sql_type(&mut reader)?;
            catalog.functions.push(Function {
                function_id,
                name,
                argument_types,
                return_type,
            });
        }

        let procedure_count = reader.read_u32("procedure count")? as usize;
        for _ in 0..procedure_count {
            let procedure_id = FunctionId::new(reader.read_u64("procedure id")?);
            let name = reader.read_string("procedure name")?;
            let argument_count = reader.read_u32("procedure argument count")? as usize;
            let mut argument_types = Vec::with_capacity(argument_count);
            for _ in 0..argument_count {
                argument_types.push(decode_sql_type(&mut reader)?);
            }
            let body = reader.read_string("procedure body")?;
            catalog.procedures.push(Procedure {
                procedure_id,
                name,
                argument_types,
                body,
            });
        }

        let operator_count = reader.read_u32("operator count")? as usize;
        for _ in 0..operator_count {
            let operator_id = OperatorId::new(reader.read_u64("operator id")?);
            let symbol = reader.read_string("operator symbol")?;
            let left_type = decode_sql_type(&mut reader)?;
            let right_type = decode_sql_type(&mut reader)?;
            let result_type = decode_sql_type(&mut reader)?;
            let function_id = FunctionId::new(reader.read_u64("operator function id")?);
            let precedence = if reader.read_bool("operator precedence present")? {
                Some(reader.read_u8("operator precedence")?)
            } else {
                None
            };
            let commutator = reader.read_optional_string("operator commutator")?;
            let negator = reader.read_optional_string("operator negator")?;
            let selectivity_function_id =
                if reader.read_bool("operator selectivity function present")? {
                    Some(FunctionId::new(
                        reader.read_u64("operator selectivity function id")?,
                    ))
                } else {
                    None
                };
            catalog.operators.push(Operator {
                operator_id,
                signature: OperatorSignature {
                    symbol,
                    left_type,
                    right_type,
                    result_type,
                    function_id,
                    precedence,
                    commutator,
                    negator,
                    selectivity_function_id,
                },
            });
        }

        let index_count = reader.read_u32("index count")? as usize;
        for _ in 0..index_count {
            let schema_name = reader.read_string("index schema")?;
            let name = reader.read_string("index name")?;
            let relation_id = RelationId::new(reader.read_u64("index relation id")?);
            let table_name = reader.read_string("index table")?;
            let unique = reader.read_bool("index unique")?;
            let method = decode_index_method(reader.read_u8("index method")?)?;
            let key_count = reader.read_u32("index key count")? as usize;
            let mut keys = Vec::with_capacity(key_count);
            for _ in 0..key_count {
                let tag = reader.read_u8("index key tag")?;
                let value = reader.read_string("index key")?;
                let key = match tag {
                    0 => IndexKey::Column(value),
                    1 => IndexKey::Expression(value),
                    unknown => {
                        return Err(RnovError::new(
                            ErrorKind::Corruption,
                            format!("unknown index key tag {unknown}"),
                        ));
                    }
                };
                keys.push(key);
            }
            let columns = keys
                .iter()
                .filter_map(|key| key.as_column().map(str::to_string))
                .collect::<Vec<_>>();
            catalog.indexes.push(Index {
                schema_name,
                name,
                relation_id,
                table_name,
                keys,
                columns,
                method,
                unique,
            });
        }

        let role_count = reader.read_u32("role count")? as usize;
        for _ in 0..role_count {
            let role_id = RoleId::new(reader.read_u64("role id")?);
            let name = reader.read_string("role name")?;
            let superuser = if version >= 10 {
                reader.read_bool("role superuser")?
            } else {
                false
            };
            catalog.roles.insert(
                name.clone(),
                Role {
                    role_id,
                    name,
                    superuser,
                },
            );
        }

        for table in catalog
            .schemas
            .values()
            .flat_map(|schema| schema.tables.values())
        {
            if let Some(owner_role_id) = table.owner_role_id {
                catalog.ensure_role_exists(owner_role_id)?;
            }
        }

        let grant_count = reader.read_u32("grant count")? as usize;
        for _ in 0..grant_count {
            catalog.grants.push(TableGrant {
                role_id: RoleId::new(reader.read_u64("grant role id")?),
                relation_id: RelationId::new(reader.read_u64("grant relation id")?),
                privilege: decode_privilege(reader.read_u8("grant privilege")?)?,
            });
        }

        if version >= 9 {
            let procedure_grant_count = reader.read_u32("procedure grant count")? as usize;
            for _ in 0..procedure_grant_count {
                let grant = ProcedureGrant {
                    role_id: RoleId::new(reader.read_u64("procedure grant role id")?),
                    procedure_id: FunctionId::new(reader.read_u64("procedure grant procedure id")?),
                    privilege: decode_privilege(reader.read_u8("procedure grant privilege")?)?,
                };
                if grant.privilege != Privilege::Execute {
                    return Err(RnovError::new(
                        ErrorKind::Corruption,
                        "procedure grant uses non-Execute privilege",
                    ));
                }
                catalog.ensure_role_exists(grant.role_id)?;
                catalog.ensure_procedure_exists(grant.procedure_id)?;
                catalog.procedure_grants.push(grant);
            }
        }

        let policy_count = reader.read_u32("policy count")? as usize;
        for _ in 0..policy_count {
            let policy = RowPolicy {
                policy_id: PolicyId::new(reader.read_u64("policy id")?),
                name: reader.read_string("policy name")?,
                relation_id: RelationId::new(reader.read_u64("policy relation id")?),
                predicate: reader.read_string("policy predicate")?,
            };
            catalog
                .row_policies
                .entry(policy.relation_id)
                .or_default()
                .push(policy);
        }

        let row_security_count = reader.read_u32("row security count")? as usize;
        for _ in 0..row_security_count {
            let relation_id = RelationId::new(reader.read_u64("row security relation id")?);
            let deny_by_default = reader.read_bool("row security deny by default")?;
            catalog.ensure_relation_exists(relation_id)?;
            catalog
                .row_security
                .insert(relation_id, RowSecurityMode { deny_by_default });
        }

        if !reader.is_complete() {
            return Err(RnovError::new(
                ErrorKind::Corruption,
                "catalog payload has trailing bytes",
            ));
        }

        Ok(catalog)
    }
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn write_optional_role_id(out: &mut Vec<u8>, value: Option<RoleId>) {
    match value {
        Some(role_id) => {
            out.push(1);
            write_u64(out, role_id.get());
        }
        None => out.push(0),
    }
}

fn read_optional_role_id(
    reader: &mut CatalogReader<'_>,
    name: &'static str,
) -> Result<Option<RoleId>> {
    if reader.read_bool(name)? {
        Ok(Some(RoleId::new(reader.read_u64(name)?)))
    } else {
        Ok(None)
    }
}

fn write_string(out: &mut Vec<u8>, value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let len = u32::try_from(bytes.len())
        .map_err(|_| RnovError::new(ErrorKind::InvalidInput, "catalog string is too large"))?;
    write_u32(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

fn write_optional_string(out: &mut Vec<u8>, value: Option<&str>) -> Result<()> {
    match value {
        Some(value) => {
            out.push(1);
            write_string(out, value)?;
        }
        None => out.push(0),
    }
    Ok(())
}

fn encode_sql_type(out: &mut Vec<u8>, data_type: &SqlType) {
    match data_type {
        SqlType::Null => out.push(0),
        SqlType::Bool => out.push(1),
        SqlType::Int64 => out.push(2),
        SqlType::UInt64 => out.push(3),
        SqlType::Float64 => out.push(10),
        SqlType::Uuid => out.push(11),
        SqlType::Text => out.push(4),
        SqlType::Bytes => out.push(5),
        SqlType::HStore => out.push(6),
        SqlType::TextVector => out.push(7),
        SqlType::Array(element) => {
            out.push(8);
            encode_sql_type(out, element);
        }
        SqlType::Range(element) => {
            out.push(9);
            encode_sql_type(out, element);
        }
    }
}

fn decode_sql_type(reader: &mut CatalogReader<'_>) -> Result<SqlType> {
    match reader.read_u8("sql type tag")? {
        0 => Ok(SqlType::Null),
        1 => Ok(SqlType::Bool),
        2 => Ok(SqlType::Int64),
        3 => Ok(SqlType::UInt64),
        10 => Ok(SqlType::Float64),
        11 => Ok(SqlType::Uuid),
        4 => Ok(SqlType::Text),
        5 => Ok(SqlType::Bytes),
        6 => Ok(SqlType::HStore),
        7 => Ok(SqlType::TextVector),
        8 => Ok(SqlType::Array(Box::new(decode_sql_type(reader)?))),
        9 => Ok(SqlType::Range(Box::new(decode_sql_type(reader)?))),
        unknown => Err(RnovError::new(
            ErrorKind::Corruption,
            format!("unknown sql type tag {unknown}"),
        )),
    }
}

fn encode_index_method(method: IndexMethod) -> u8 {
    match method {
        IndexMethod::BTree => 0,
        IndexMethod::Hash => 1,
        IndexMethod::Gin => 2,
        IndexMethod::Gist => 3,
        IndexMethod::Brin => 4,
    }
}

fn decode_index_method(raw: u8) -> Result<IndexMethod> {
    match raw {
        0 => Ok(IndexMethod::BTree),
        1 => Ok(IndexMethod::Hash),
        2 => Ok(IndexMethod::Gin),
        3 => Ok(IndexMethod::Gist),
        4 => Ok(IndexMethod::Brin),
        unknown => Err(RnovError::new(
            ErrorKind::Corruption,
            format!("unknown index method tag {unknown}"),
        )),
    }
}

fn encode_privilege(privilege: Privilege) -> u8 {
    match privilege {
        Privilege::Select => 0,
        Privilege::Insert => 1,
        Privilege::Update => 2,
        Privilege::Delete => 3,
        Privilege::Execute => 4,
    }
}

fn decode_privilege(raw: u8) -> Result<Privilege> {
    match raw {
        0 => Ok(Privilege::Select),
        1 => Ok(Privilege::Insert),
        2 => Ok(Privilege::Update),
        3 => Ok(Privilege::Delete),
        4 => Ok(Privilege::Execute),
        unknown => Err(RnovError::new(
            ErrorKind::Corruption,
            format!("unknown privilege tag {unknown}"),
        )),
    }
}

struct CatalogReader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> CatalogReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_bool(&mut self, name: &'static str) -> Result<bool> {
        match self.read_u8(name)? {
            0 => Ok(false),
            1 => Ok(true),
            value => Err(RnovError::new(
                ErrorKind::Corruption,
                format!("invalid boolean value {value}"),
            )),
        }
    }

    fn read_u8(&mut self, name: &'static str) -> Result<u8> {
        Ok(self.read_exact(1, name)?[0])
    }

    fn read_u16(&mut self, name: &'static str) -> Result<u16> {
        Ok(u16::from_be_bytes(self.read_fixed::<2>(name)?))
    }

    fn read_u32(&mut self, name: &'static str) -> Result<u32> {
        Ok(u32::from_be_bytes(self.read_fixed::<4>(name)?))
    }

    fn read_u64(&mut self, name: &'static str) -> Result<u64> {
        Ok(u64::from_be_bytes(self.read_fixed::<8>(name)?))
    }

    fn read_string(&mut self, name: &'static str) -> Result<String> {
        let len = self.read_u32(name)? as usize;
        let bytes = self.read_exact(len, name)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| {
            RnovError::new(ErrorKind::Corruption, format!("{name} is not valid utf-8"))
        })
    }

    fn read_optional_string(&mut self, name: &'static str) -> Result<Option<String>> {
        if self.read_bool(name)? {
            self.read_string(name).map(Some)
        } else {
            Ok(None)
        }
    }

    fn read_fixed<const N: usize>(&mut self, name: &'static str) -> Result<[u8; N]> {
        let bytes = self.read_exact(N, name)?;
        let mut array = [0_u8; N];
        array.copy_from_slice(bytes);
        Ok(array)
    }

    fn read_exact(&mut self, len: usize, name: &'static str) -> Result<&'a [u8]> {
        let end = self.position.checked_add(len).ok_or_else(|| {
            RnovError::new(ErrorKind::Corruption, format!("{name} length overflow"))
        })?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| RnovError::new(ErrorKind::Corruption, format!("truncated {name}")))?;
        self.position = end;
        Ok(bytes)
    }

    fn is_complete(&self) -> bool {
        self.position == self.bytes.len()
    }
}
