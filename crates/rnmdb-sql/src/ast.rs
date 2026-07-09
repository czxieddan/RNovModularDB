use std::fmt;

use rnmdb_catalog::{Column, IndexMethod, OperatorSignature, Privilege};
use rnmdb_common::ids::{FunctionId, RelationId, RoleId};
use rnmdb_types::{SqlFloat64, SqlType};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Ident(String);

impl Ident {
    pub fn new(value: impl AsRef<str>) -> Self {
        Self(value.as_ref().to_ascii_lowercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Ident {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectName {
    schema: Option<Ident>,
    object: Ident,
}

impl ObjectName {
    pub fn qualified(schema: impl AsRef<str>, object: impl AsRef<str>) -> Self {
        Self {
            schema: Some(Ident::new(schema)),
            object: Ident::new(object),
        }
    }

    pub fn unqualified(object: impl AsRef<str>) -> Self {
        Self {
            schema: None,
            object: Ident::new(object),
        }
    }

    pub fn schema(&self) -> Option<&str> {
        self.schema.as_ref().map(Ident::as_str)
    }

    pub fn object(&self) -> &str {
        self.object.as_str()
    }
}

impl fmt::Display for ObjectName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(schema) = &self.schema {
            write!(f, "{schema}.{}", self.object)
        } else {
            write!(f, "{}", self.object)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColumnDef {
    pub name: Ident,
    pub data_type: SqlType,
    pub nullable: bool,
    pub encrypted: bool,
    pub generated: Option<GeneratedColumn>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GeneratedColumn {
    pub expr: Expr,
    pub stored: bool,
}

impl ColumnDef {
    pub fn to_catalog_column(&self) -> Column {
        let mut column = Column::new(self.name.as_str(), self.data_type.clone());
        if !self.nullable {
            column = column.not_null();
        }
        if self.encrypted {
            column = column.encrypted();
        }
        if let Some(generated) = &self.generated {
            column = column.generated(generated.expr.to_string(), generated.stored);
        }
        column
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expr {
    Identifier(Ident),
    QualifiedIdentifier {
        qualifier: Ident,
        name: Ident,
    },
    Integer(i64),
    Float64(SqlFloat64),
    String(String),
    Bool(bool),
    Null,
    CountStar,
    Count(Box<Expr>),
    CountDistinct(Box<Expr>),
    Sum(Box<Expr>),
    Min(Box<Expr>),
    Max(Box<Expr>),
    RowNumberOver {
        order_by: Vec<OrderByExpr>,
    },
    RankOver {
        order_by: Vec<OrderByExpr>,
    },
    DenseRankOver {
        order_by: Vec<OrderByExpr>,
    },
    Array(Vec<Expr>),
    HStore(Vec<(String, Option<String>)>),
    Range {
        lower: Box<Expr>,
        upper: Box<Expr>,
        bounds: RangeLiteralBounds,
    },
    Binary {
        left: Box<Expr>,
        op: String,
        right: Box<Expr>,
    },
    Unary {
        op: String,
        expr: Box<Expr>,
    },
    Not(Box<Expr>),
    IsNull {
        expr: Box<Expr>,
        negated: bool,
    },
    IsTruth {
        expr: Box<Expr>,
        value: bool,
        negated: bool,
    },
    IsUnknown {
        expr: Box<Expr>,
        negated: bool,
    },
    IsDistinctFrom {
        left: Box<Expr>,
        right: Box<Expr>,
        negated: bool,
    },
    Between {
        expr: Box<Expr>,
        low: Box<Expr>,
        high: Box<Expr>,
        negated: bool,
    },
    InList {
        expr: Box<Expr>,
        values: Vec<Expr>,
        negated: bool,
    },
    Like {
        expr: Box<Expr>,
        pattern: Box<Expr>,
        negated: bool,
    },
    Coalesce(Vec<Expr>),
    NullIf {
        left: Box<Expr>,
        right: Box<Expr>,
    },
    Case {
        operand: Option<Box<Expr>>,
        whens: Vec<CaseWhen>,
        else_expr: Option<Box<Expr>>,
    },
    Cast {
        expr: Box<Expr>,
        data_type: SqlType,
    },
    Call {
        name: ObjectName,
        args: Vec<Expr>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaseWhen {
    pub condition: Expr,
    pub result: Expr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RangeLiteralBounds {
    pub lower_inclusive: bool,
    pub upper_inclusive: bool,
}

impl RangeLiteralBounds {
    pub fn parse(raw: &str) -> Option<Self> {
        let bytes = raw.as_bytes();
        if bytes.len() != 2 {
            return None;
        }

        let lower_inclusive = match bytes[0] {
            b'[' => true,
            b'(' => false,
            _ => return None,
        };
        let upper_inclusive = match bytes[1] {
            b']' => true,
            b')' => false,
            _ => return None,
        };

        Some(Self {
            lower_inclusive,
            upper_inclusive,
        })
    }

    fn as_str(self) -> &'static str {
        match (self.lower_inclusive, self.upper_inclusive) {
            (true, true) => "[]",
            (true, false) => "[)",
            (false, true) => "(]",
            (false, false) => "()",
        }
    }
}

impl fmt::Display for Expr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identifier(ident) => write!(f, "{ident}"),
            Self::QualifiedIdentifier { qualifier, name } => write!(f, "{qualifier}.{name}"),
            Self::Integer(value) => write!(f, "{value}"),
            Self::Float64(value) => write!(f, "{}", value.get()),
            Self::String(value) => write!(f, "'{}'", value.replace('\'', "''")),
            Self::Bool(true) => f.write_str("TRUE"),
            Self::Bool(false) => f.write_str("FALSE"),
            Self::Null => f.write_str("NULL"),
            Self::CountStar => f.write_str("count(*)"),
            Self::Count(expr) => write!(f, "count({expr})"),
            Self::CountDistinct(expr) => write!(f, "count(DISTINCT {expr})"),
            Self::Sum(expr) => write!(f, "sum({expr})"),
            Self::Min(expr) => write!(f, "min({expr})"),
            Self::Max(expr) => write!(f, "max({expr})"),
            Self::RowNumberOver { order_by } => write_window_function(f, "row_number", order_by),
            Self::RankOver { order_by } => write_window_function(f, "rank", order_by),
            Self::DenseRankOver { order_by } => write_window_function(f, "dense_rank", order_by),
            Self::Array(values) => {
                f.write_str("ARRAY[")?;
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{value}")?;
                }
                f.write_str("]")
            }
            Self::HStore(entries) => {
                f.write_str("HSTORE(")?;
                for (index, (key, value)) in entries.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "'{}' => ", key.replace('\'', "''"))?;
                    if let Some(value) = value {
                        write!(f, "'{}'", value.replace('\'', "''"))?;
                    } else {
                        f.write_str("NULL")?;
                    }
                }
                f.write_str(")")
            }
            Self::Range {
                lower,
                upper,
                bounds,
            } => write!(f, "RANGE({lower}, {upper}, '{}')", bounds.as_str()),
            Self::Binary { left, op, right } => write!(f, "{left} {op} {right}"),
            Self::Unary { op, expr } => write!(f, "{op}{expr}"),
            Self::Not(expr) => write!(f, "NOT {expr}"),
            Self::IsNull { expr, negated } => {
                if *negated {
                    write!(f, "{expr} IS NOT NULL")
                } else {
                    write!(f, "{expr} IS NULL")
                }
            }
            Self::IsTruth {
                expr,
                value,
                negated,
            } => {
                let value = if *value { "TRUE" } else { "FALSE" };
                if *negated {
                    write!(f, "{expr} IS NOT {value}")
                } else {
                    write!(f, "{expr} IS {value}")
                }
            }
            Self::IsUnknown { expr, negated } => {
                if *negated {
                    write!(f, "{expr} IS NOT UNKNOWN")
                } else {
                    write!(f, "{expr} IS UNKNOWN")
                }
            }
            Self::IsDistinctFrom {
                left,
                right,
                negated,
            } => {
                if *negated {
                    write!(f, "{left} IS NOT DISTINCT FROM {right}")
                } else {
                    write!(f, "{left} IS DISTINCT FROM {right}")
                }
            }
            Self::Between {
                expr,
                low,
                high,
                negated,
            } => {
                if *negated {
                    write!(f, "{expr} NOT BETWEEN {low} AND {high}")
                } else {
                    write!(f, "{expr} BETWEEN {low} AND {high}")
                }
            }
            Self::InList {
                expr,
                values,
                negated,
            } => {
                if *negated {
                    write!(f, "{expr} NOT IN (")?;
                } else {
                    write!(f, "{expr} IN (")?;
                }
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{value}")?;
                }
                f.write_str(")")
            }
            Self::Like {
                expr,
                pattern,
                negated,
            } => {
                if *negated {
                    write!(f, "{expr} NOT LIKE {pattern}")
                } else {
                    write!(f, "{expr} LIKE {pattern}")
                }
            }
            Self::Coalesce(values) => {
                f.write_str("coalesce(")?;
                for (index, value) in values.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{value}")?;
                }
                f.write_str(")")
            }
            Self::NullIf { left, right } => write!(f, "nullif({left}, {right})"),
            Self::Case {
                operand,
                whens,
                else_expr,
            } => {
                f.write_str("CASE")?;
                if let Some(operand) = operand {
                    write!(f, " {operand}")?;
                }
                for arm in whens {
                    write!(f, " WHEN {} THEN {}", arm.condition, arm.result)?;
                }
                if let Some(else_expr) = else_expr {
                    write!(f, " ELSE {else_expr}")?;
                }
                f.write_str(" END")
            }
            Self::Cast { expr, data_type } => {
                write!(f, "CAST({expr} AS {})", format_sql_type(data_type))
            }
            Self::Call { name, args } => {
                write!(f, "{name}(")?;
                for (index, arg) in args.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    write!(f, "{arg}")?;
                }
                f.write_str(")")
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SelectItem {
    Wildcard,
    Expr { expr: Expr, alias: Option<Ident> },
}

impl fmt::Display for SelectItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wildcard => f.write_str("*"),
            Self::Expr { expr, alias } => {
                write!(f, "{expr}")?;
                if let Some(alias) = alias {
                    write!(f, " AS {alias}")?;
                }
                Ok(())
            }
        }
    }
}

fn write_window_function(
    f: &mut fmt::Formatter<'_>,
    name: &str,
    order_by: &[OrderByExpr],
) -> fmt::Result {
    write!(f, "{name}() OVER (ORDER BY ")?;
    for (index, order_by) in order_by.iter().enumerate() {
        if index > 0 {
            f.write_str(", ")?;
        }
        write!(f, "{order_by}")?;
    }
    f.write_str(")")
}

fn format_sql_type(data_type: &SqlType) -> String {
    match data_type {
        SqlType::Null => "NULL".to_string(),
        SqlType::Bool => "BOOL".to_string(),
        SqlType::Int64 => "INT64".to_string(),
        SqlType::UInt64 => "UINT64".to_string(),
        SqlType::Float64 => "FLOAT64".to_string(),
        SqlType::Uuid => "UUID".to_string(),
        SqlType::Timestamp => "TIMESTAMP".to_string(),
        SqlType::Json => "JSON".to_string(),
        SqlType::Text => "TEXT".to_string(),
        SqlType::Bytes => "BYTES".to_string(),
        SqlType::HStore => "HSTORE".to_string(),
        SqlType::TextVector => "TEXTVECTOR".to_string(),
        SqlType::Array(element_type) => format!("{}[]", format_sql_type(element_type)),
        SqlType::Range(element_type) => format!("RANGE<{}>", format_sql_type(element_type)),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SortDirection {
    Asc,
    Desc,
    AscNullsFirst,
    AscNullsLast,
    DescNullsFirst,
    DescNullsLast,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderByExpr {
    pub expr: Expr,
    pub direction: SortDirection,
}

impl fmt::Display for OrderByExpr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.expr, sort_direction_name(self.direction))
    }
}

fn sort_direction_name(direction: SortDirection) -> &'static str {
    match direction {
        SortDirection::Asc => "ASC",
        SortDirection::Desc => "DESC",
        SortDirection::AscNullsFirst => "ASC NULLS FIRST",
        SortDirection::AscNullsLast => "ASC NULLS LAST",
        SortDirection::DescNullsFirst => "DESC NULLS FIRST",
        SortDirection::DescNullsLast => "DESC NULLS LAST",
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Assignment {
    pub column: Ident,
    pub value: Expr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LateralJoin {
    pub table: ObjectName,
    pub on: Expr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JoinKind {
    Inner,
    Left,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinClause {
    pub kind: JoinKind,
    pub table: ObjectName,
    pub on: Expr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecursiveCte {
    pub name: ObjectName,
    pub columns: Vec<Ident>,
    pub seed: Box<Statement>,
    pub recursive: Box<Statement>,
    pub query: Box<Statement>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexKeyDef {
    Column(Ident),
    Expression(Expr),
}

impl fmt::Display for IndexKeyDef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Column(column) => write!(f, "{column}"),
            Self::Expression(expr) => write!(f, "({expr})"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionAction {
    Begin,
    Commit,
    Rollback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExplainFormat {
    Logical,
    Costs,
    Physical,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Statement {
    CreateTable {
        name: ObjectName,
        columns: Vec<ColumnDef>,
        if_not_exists: bool,
    },
    CreateIndex {
        name: ObjectName,
        table: ObjectName,
        keys: Vec<IndexKeyDef>,
        method: IndexMethod,
        unique: bool,
        if_not_exists: bool,
    },
    AlterTableAddColumn {
        table: ObjectName,
        column: ColumnDef,
        if_not_exists: bool,
    },
    AlterColumnEncryption {
        table: ObjectName,
        column: Ident,
        encrypted: bool,
    },
    DropTable {
        name: ObjectName,
        if_exists: bool,
    },
    DropIndex {
        name: ObjectName,
        if_exists: bool,
    },
    DropFunction {
        name: Ident,
        argument_types: Vec<SqlType>,
        if_exists: bool,
    },
    DropProcedure {
        name: Ident,
        argument_types: Vec<SqlType>,
        if_exists: bool,
    },
    DropOperator {
        symbol: String,
        left_type: SqlType,
        right_type: SqlType,
        if_exists: bool,
    },
    DropRole {
        name: Ident,
        if_exists: bool,
    },
    DropPolicy {
        name: Ident,
        table: ObjectName,
        if_exists: bool,
    },
    CreateFunction {
        name: Ident,
        argument_types: Vec<SqlType>,
        return_type: SqlType,
        if_not_exists: bool,
    },
    CreateProcedure {
        name: Ident,
        argument_types: Vec<SqlType>,
        body: String,
        if_not_exists: bool,
    },
    CreateOperator {
        symbol: String,
        left_type: SqlType,
        right_type: SqlType,
        result_type: SqlType,
        function: Ident,
        precedence: Option<u8>,
        commutator: Option<String>,
        negator: Option<String>,
        selectivity: Option<Ident>,
    },
    CreateRole {
        name: Ident,
        if_not_exists: bool,
    },
    CreatePolicy {
        name: Ident,
        table: ObjectName,
        predicate: Expr,
        if_not_exists: bool,
    },
    GrantTablePrivilege {
        privilege: Privilege,
        table: ObjectName,
        role: Ident,
    },
    GrantProcedurePrivilege {
        privilege: Privilege,
        name: Ident,
        argument_types: Vec<SqlType>,
        role: Ident,
    },
    CallProcedure {
        name: Ident,
        args: Vec<Expr>,
    },
    Insert {
        table: ObjectName,
        columns: Vec<Ident>,
        values: Vec<Expr>,
    },
    Update {
        table: ObjectName,
        assignments: Vec<Assignment>,
        selection: Option<Expr>,
    },
    Delete {
        table: ObjectName,
        selection: Option<Expr>,
    },
    Select {
        distinct: bool,
        projection: Vec<SelectItem>,
        from: ObjectName,
        selection: Option<Expr>,
        group_by: Vec<Expr>,
        having: Option<Expr>,
        order_by: Vec<OrderByExpr>,
        limit: Option<usize>,
        offset: Option<usize>,
    },
    SelectJoin {
        distinct: bool,
        projection: Vec<SelectItem>,
        from: ObjectName,
        join: JoinClause,
        selection: Option<Expr>,
        group_by: Vec<Expr>,
        having: Option<Expr>,
        order_by: Vec<OrderByExpr>,
        limit: Option<usize>,
        offset: Option<usize>,
    },
    SelectLateral {
        distinct: bool,
        projection: Vec<SelectItem>,
        from: ObjectName,
        lateral_join: LateralJoin,
        selection: Option<Expr>,
        group_by: Vec<Expr>,
        having: Option<Expr>,
        order_by: Vec<OrderByExpr>,
        limit: Option<usize>,
        offset: Option<usize>,
    },
    SelectGroupingSets {
        distinct: bool,
        projection: Vec<SelectItem>,
        from: ObjectName,
        selection: Option<Expr>,
        group_by: Vec<Expr>,
        grouping_sets: Vec<Vec<Expr>>,
        having: Option<Expr>,
        order_by: Vec<OrderByExpr>,
        limit: Option<usize>,
        offset: Option<usize>,
    },
    Union {
        all: bool,
        left: Box<Statement>,
        right: Box<Statement>,
    },
    Intersect {
        all: bool,
        left: Box<Statement>,
        right: Box<Statement>,
    },
    Except {
        all: bool,
        left: Box<Statement>,
        right: Box<Statement>,
    },
    RecursiveCte {
        name: ObjectName,
        columns: Vec<Ident>,
        seed: Box<Statement>,
        recursive: Box<Statement>,
        query: Box<Statement>,
    },
    Query {
        input: Box<Statement>,
        order_by: Vec<OrderByExpr>,
        limit: Option<usize>,
        offset: Option<usize>,
    },
    Transaction {
        action: TransactionAction,
    },
    Explain {
        analyze: bool,
        format: ExplainFormat,
        statement: Box<Statement>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundColumn {
    pub name: String,
    pub data_type: SqlType,
    pub nullable: bool,
    pub encrypted: bool,
    pub generated: Option<GeneratedColumn>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundIndexKey {
    Column(BoundColumn),
    Expression { expr: Expr, data_type: SqlType },
}

impl BoundIndexKey {
    pub fn display_name(&self) -> String {
        match self {
            Self::Column(column) => column.name.clone(),
            Self::Expression { expr, .. } => expr.to_string(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundSelect {
    pub relation_id: RelationId,
    pub table: ObjectName,
    pub lateral_join: Option<BoundLateralJoin>,
    pub distinct: bool,
    pub projection: Vec<BoundSelectItem>,
    pub hidden_group_keys: Vec<BoundSelectItem>,
    pub hidden_aggregates: Vec<BoundSelectItem>,
    pub columns: Vec<BoundColumn>,
    pub selection: Option<Expr>,
    pub group_by: Vec<Expr>,
    pub grouping_sets: Vec<Vec<Expr>>,
    pub having: Option<Expr>,
    pub order_by: Vec<OrderByExpr>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub applied_row_policies: Vec<String>,
    pub row_policy_predicates: Vec<BoundRowPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundLateralJoin {
    pub inner_relation_id: RelationId,
    pub inner_table: ObjectName,
    pub inner_column: String,
    pub outer_column: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundJoin {
    pub kind: JoinKind,
    pub right_relation_id: RelationId,
    pub right_table: ObjectName,
    pub predicate: Expr,
    pub applied_row_policies: Vec<String>,
    pub row_policy_predicates: Vec<BoundRowPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundJoinSelect {
    pub select: BoundSelect,
    pub join: BoundJoin,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundUnion {
    pub all: bool,
    pub columns: Vec<BoundColumn>,
    pub left: Box<BoundStatement>,
    pub right: Box<BoundStatement>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundIntersect {
    pub all: bool,
    pub columns: Vec<BoundColumn>,
    pub left: Box<BoundStatement>,
    pub right: Box<BoundStatement>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundExcept {
    pub all: bool,
    pub columns: Vec<BoundColumn>,
    pub left: Box<BoundStatement>,
    pub right: Box<BoundStatement>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundQuery {
    pub columns: Vec<BoundColumn>,
    pub input: Box<BoundStatement>,
    pub order_by: Vec<OrderByExpr>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundRecursiveCte {
    pub name: ObjectName,
    pub columns: Vec<BoundColumn>,
    pub seed: Box<BoundStatement>,
    pub recursive: Box<BoundStatement>,
    pub query: BoundSelect,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundSelectItem {
    pub column: BoundColumn,
    pub expr: Expr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundAssignment {
    pub column: BoundColumn,
    pub value: Expr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundRowPolicy {
    pub name: String,
    pub predicate: Expr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundUpdate {
    pub relation_id: RelationId,
    pub table: ObjectName,
    pub assignments: Vec<BoundAssignment>,
    pub selection: Option<Expr>,
    pub applied_row_policies: Vec<String>,
    pub row_policy_predicates: Vec<BoundRowPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundDelete {
    pub relation_id: RelationId,
    pub table: ObjectName,
    pub selection: Option<Expr>,
    pub applied_row_policies: Vec<String>,
    pub row_policy_predicates: Vec<BoundRowPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BoundStatement {
    CreateTable {
        name: ObjectName,
        columns: Vec<ColumnDef>,
        if_not_exists: bool,
    },
    CreateIndex {
        name: ObjectName,
        relation_id: RelationId,
        table: ObjectName,
        keys: Vec<BoundIndexKey>,
        method: IndexMethod,
        unique: bool,
        if_not_exists: bool,
    },
    AlterTableAddColumn {
        relation_id: RelationId,
        table: ObjectName,
        column: ColumnDef,
        if_not_exists: bool,
    },
    AlterColumnEncryption {
        relation_id: RelationId,
        table: ObjectName,
        column: Ident,
        encrypted: bool,
    },
    DropTable {
        relation_id: Option<RelationId>,
        name: ObjectName,
        if_exists: bool,
    },
    DropIndex {
        name: ObjectName,
        if_exists: bool,
    },
    DropFunction {
        name: Ident,
        argument_types: Vec<SqlType>,
        if_exists: bool,
    },
    DropProcedure {
        name: Ident,
        argument_types: Vec<SqlType>,
        if_exists: bool,
    },
    DropOperator {
        symbol: String,
        left_type: SqlType,
        right_type: SqlType,
        if_exists: bool,
    },
    DropRole {
        name: Ident,
        if_exists: bool,
    },
    DropPolicy {
        name: Ident,
        relation_id: RelationId,
        if_exists: bool,
    },
    CreateFunction {
        name: Ident,
        argument_types: Vec<SqlType>,
        return_type: SqlType,
        if_not_exists: bool,
    },
    CreateProcedure {
        name: Ident,
        argument_types: Vec<SqlType>,
        body: String,
        if_not_exists: bool,
    },
    CreateOperator {
        signature: OperatorSignature,
    },
    CreateRole {
        name: Ident,
        if_not_exists: bool,
    },
    CreatePolicy {
        name: Ident,
        relation_id: RelationId,
        predicate: String,
        if_not_exists: bool,
    },
    GrantTablePrivilege {
        role_id: RoleId,
        relation_id: RelationId,
        privilege: Privilege,
    },
    GrantProcedurePrivilege {
        role_id: RoleId,
        procedure_id: FunctionId,
        privilege: Privilege,
    },
    CallProcedure {
        name: Ident,
        body: String,
        args: Vec<Expr>,
    },
    Insert {
        table: ObjectName,
        columns: Vec<BoundColumn>,
        values: Vec<Expr>,
    },
    Update(BoundUpdate),
    Delete(BoundDelete),
    Select(BoundSelect),
    SelectJoin(BoundJoinSelect),
    Union(BoundUnion),
    Intersect(BoundIntersect),
    Except(BoundExcept),
    RecursiveCte(BoundRecursiveCte),
    Query(BoundQuery),
    Transaction {
        action: TransactionAction,
    },
    Explain {
        analyze: bool,
        format: ExplainFormat,
        statement: Box<BoundStatement>,
    },
}
