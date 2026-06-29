use std::collections::BTreeMap;

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
    indexes: Vec<Index>,
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
            indexes: Vec::new(),
            roles: BTreeMap::new(),
            grants: Vec::new(),
            row_policies: BTreeMap::new(),
        }
    }

    pub fn database_id(&self) -> DatabaseId {
        self.database_id
    }

    pub fn functions(&self) -> &[Function] {
        &self.functions
    }

    pub fn get_function(&self, name: &str, argument_types: &[SqlType]) -> Option<&Function> {
        self.functions
            .iter()
            .find(|function| function.name == name && function.argument_types == argument_types)
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
            },
        );
        Ok(schema.tables.get(&table_name).expect("table inserted"))
    }

    pub fn get_table(&self, schema_name: &str, table_name: &str) -> Option<&Table> {
        self.schemas.get(schema_name)?.tables.get(table_name)
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
        validate_index_columns(table, &columns)?;
        let index = Index {
            schema_name: schema_name.to_string(),
            name: index_name,
            relation_id,
            table_name: table.name.clone(),
            columns,
            method,
            unique,
        };
        self.indexes.push(index.clone());
        Ok(index)
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

    fn table_by_relation_id(&self, relation_id: RelationId) -> Option<&Table> {
        self.schemas
            .values()
            .flat_map(|schema| schema.tables.values())
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

fn validate_index_columns(table: &Table, columns: &[String]) -> Result<()> {
    if columns.is_empty() {
        return Err(RnovError::new(
            ErrorKind::InvalidInput,
            "index must have at least one column",
        ));
    }

    let mut seen = BTreeMap::new();
    for column in columns {
        validate_identifier("index column", column)?;
        if seen.insert(column.as_str(), ()).is_some() {
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
    Ok(())
}

pub struct CatalogCodec;

impl CatalogCodec {
    const MAGIC: [u8; 8] = *b"RNOVCAT1";
    const VERSION: u16 = 4;

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

        write_u32(&mut out, catalog.operators.len() as u32);
        for operator in &catalog.operators {
            write_u64(&mut out, operator.operator_id.get());
            write_string(&mut out, &operator.signature.symbol)?;
            encode_sql_type(&mut out, &operator.signature.left_type);
            encode_sql_type(&mut out, &operator.signature.right_type);
            encode_sql_type(&mut out, &operator.signature.result_type);
            write_u64(&mut out, operator.signature.function_id.get());
        }

        write_u32(&mut out, catalog.indexes.len() as u32);
        for index in &catalog.indexes {
            write_string(&mut out, &index.schema_name)?;
            write_string(&mut out, &index.name)?;
            write_u64(&mut out, index.relation_id.get());
            write_string(&mut out, &index.table_name)?;
            out.push(u8::from(index.unique));
            out.push(encode_index_method(index.method));
            write_u32(&mut out, index.columns.len() as u32);
            for column in &index.columns {
                write_string(&mut out, column)?;
            }
        }

        write_u32(&mut out, catalog.roles.len() as u32);
        for role in catalog.roles.values() {
            write_u64(&mut out, role.role_id.get());
            write_string(&mut out, &role.name)?;
        }

        write_u32(&mut out, catalog.grants.len() as u32);
        for grant in &catalog.grants {
            write_u64(&mut out, grant.role_id.get());
            write_u64(&mut out, grant.relation_id.get());
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
        if version != Self::VERSION {
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
            operators: Vec::new(),
            indexes: Vec::new(),
            roles: BTreeMap::new(),
            grants: Vec::new(),
            row_policies: BTreeMap::new(),
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
                let version = reader.read_u64("table version")?;
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
                        version,
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

        let operator_count = reader.read_u32("operator count")? as usize;
        for _ in 0..operator_count {
            let operator_id = OperatorId::new(reader.read_u64("operator id")?);
            let symbol = reader.read_string("operator symbol")?;
            let left_type = decode_sql_type(&mut reader)?;
            let right_type = decode_sql_type(&mut reader)?;
            let result_type = decode_sql_type(&mut reader)?;
            let function_id = FunctionId::new(reader.read_u64("operator function id")?);
            catalog.operators.push(Operator {
                operator_id,
                signature: OperatorSignature {
                    symbol,
                    left_type,
                    right_type,
                    result_type,
                    function_id,
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
            let column_count = reader.read_u32("index column count")? as usize;
            let mut columns = Vec::with_capacity(column_count);
            for _ in 0..column_count {
                columns.push(reader.read_string("index column")?);
            }
            catalog.indexes.push(Index {
                schema_name,
                name,
                relation_id,
                table_name,
                columns,
                method,
                unique,
            });
        }

        let role_count = reader.read_u32("role count")? as usize;
        for _ in 0..role_count {
            let role_id = RoleId::new(reader.read_u64("role id")?);
            let name = reader.read_string("role name")?;
            catalog.roles.insert(name.clone(), Role { role_id, name });
        }

        let grant_count = reader.read_u32("grant count")? as usize;
        for _ in 0..grant_count {
            catalog.grants.push(TableGrant {
                role_id: RoleId::new(reader.read_u64("grant role id")?),
                relation_id: RelationId::new(reader.read_u64("grant relation id")?),
                privilege: decode_privilege(reader.read_u8("grant privilege")?)?,
            });
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

fn write_string(out: &mut Vec<u8>, value: &str) -> Result<()> {
    let bytes = value.as_bytes();
    let len = u32::try_from(bytes.len())
        .map_err(|_| RnovError::new(ErrorKind::InvalidInput, "catalog string is too large"))?;
    write_u32(out, len);
    out.extend_from_slice(bytes);
    Ok(())
}

fn encode_sql_type(out: &mut Vec<u8>, data_type: &SqlType) {
    match data_type {
        SqlType::Null => out.push(0),
        SqlType::Bool => out.push(1),
        SqlType::Int64 => out.push(2),
        SqlType::UInt64 => out.push(3),
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
