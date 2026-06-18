use std::collections::BTreeMap;

use rnovdb_common::{
    error::{ErrorKind, Result, RnovError},
    ids::{DatabaseId, FunctionId, OperatorId, PolicyId, RelationId, RoleId},
};
use rnovdb_types::SqlType;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Column {
    name: String,
    data_type: SqlType,
    nullable: bool,
    encrypted: bool,
}

impl Column {
    pub fn new(name: impl Into<String>, data_type: SqlType) -> Self {
        Self {
            name: name.into(),
            data_type,
            nullable: true,
            encrypted: false,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Table {
    relation_id: RelationId,
    schema_name: String,
    name: String,
    columns: Vec<Column>,
    version: u64,
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
    operators: Vec<Operator>,
    roles: BTreeMap<String, Role>,
    grants: Vec<TableGrant>,
    row_policies: BTreeMap<RelationId, Vec<RowPolicy>>,
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
            operators: Vec::new(),
            roles: BTreeMap::new(),
            grants: Vec::new(),
            row_policies: BTreeMap::new(),
        }
    }

    pub fn database_id(&self) -> DatabaseId {
        self.database_id
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
            },
        );
        Ok(schema.tables.get(&table_name).expect("table inserted"))
    }

    pub fn get_table(&self, schema_name: &str, table_name: &str) -> Option<&Table> {
        self.schemas.get(schema_name)?.tables.get(table_name)
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

    pub fn create_role(&mut self, name: impl Into<String>) -> Result<Role> {
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
        };
        self.next_role_id += 1;
        self.roles.insert(name, role.clone());
        Ok(role)
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

    fn ensure_role_exists(&self, role_id: RoleId) -> Result<()> {
        if self.roles.values().any(|role| role.role_id == role_id) {
            return Ok(());
        }
        Err(RnovError::new(ErrorKind::NotFound, "role does not exist"))
    }

    fn ensure_relation_exists(&self, relation_id: RelationId) -> Result<()> {
        if self.schemas.values().any(|schema| {
            schema
                .tables
                .values()
                .any(|table| table.relation_id == relation_id)
        }) {
            return Ok(());
        }
        Err(RnovError::new(
            ErrorKind::NotFound,
            "relation does not exist",
        ))
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
pub struct OperatorSignature {
    symbol: String,
    left_type: SqlType,
    right_type: SqlType,
    result_type: SqlType,
    function_id: FunctionId,
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
        }
    }

    pub fn symbol(&self) -> &str {
        &self.symbol
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

    pub fn symbol(&self) -> &str {
        self.signature.symbol()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Role {
    role_id: RoleId,
    name: String,
}

impl Role {
    pub fn role_id(&self) -> RoleId {
        self.role_id
    }

    pub fn name(&self) -> &str {
        &self.name
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TableGrant {
    role_id: RoleId,
    relation_id: RelationId,
    privilege: Privilege,
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
