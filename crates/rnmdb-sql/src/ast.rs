use std::fmt;

use rnmdb_catalog::{Column, OperatorSignature, Privilege};
use rnmdb_common::ids::{RelationId, RoleId};
use rnmdb_types::SqlType;

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
        column
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Expr {
    Identifier(Ident),
    Integer(i64),
    String(String),
    Null,
    CountStar,
    Count(Box<Expr>),
    Sum(Box<Expr>),
    Min(Box<Expr>),
    Max(Box<Expr>),
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
    Not(Box<Expr>),
    IsNull {
        expr: Box<Expr>,
        negated: bool,
    },
    Call {
        name: ObjectName,
        args: Vec<Expr>,
    },
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
            Self::Integer(value) => write!(f, "{value}"),
            Self::String(value) => write!(f, "'{}'", value.replace('\'', "''")),
            Self::Null => f.write_str("NULL"),
            Self::CountStar => f.write_str("count(*)"),
            Self::Count(expr) => write!(f, "count({expr})"),
            Self::Sum(expr) => write!(f, "sum({expr})"),
            Self::Min(expr) => write!(f, "min({expr})"),
            Self::Max(expr) => write!(f, "max({expr})"),
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
            Self::Not(expr) => write!(f, "NOT {expr}"),
            Self::IsNull { expr, negated } => {
                if *negated {
                    write!(f, "{expr} IS NOT NULL")
                } else {
                    write!(f, "{expr} IS NULL")
                }
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SortDirection {
    Asc,
    Desc,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderByExpr {
    pub expr: Expr,
    pub direction: SortDirection,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Assignment {
    pub column: Ident,
    pub value: Expr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionAction {
    Begin,
    Commit,
    Rollback,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Statement {
    CreateTable {
        name: ObjectName,
        columns: Vec<ColumnDef>,
    },
    AlterTableAddColumn {
        table: ObjectName,
        column: ColumnDef,
    },
    DropTable {
        name: ObjectName,
        if_exists: bool,
    },
    CreateFunction {
        name: Ident,
        argument_types: Vec<SqlType>,
        return_type: SqlType,
    },
    CreateOperator {
        symbol: String,
        left_type: SqlType,
        right_type: SqlType,
        result_type: SqlType,
        function: Ident,
    },
    CreateRole {
        name: Ident,
    },
    CreatePolicy {
        name: Ident,
        table: ObjectName,
        predicate: Expr,
    },
    GrantTablePrivilege {
        privilege: Privilege,
        table: ObjectName,
        role: Ident,
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
    Transaction {
        action: TransactionAction,
    },
    Explain {
        analyze: bool,
        statement: Box<Statement>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundColumn {
    pub name: String,
    pub data_type: SqlType,
    pub nullable: bool,
    pub encrypted: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundSelect {
    pub relation_id: RelationId,
    pub table: ObjectName,
    pub distinct: bool,
    pub projection: Vec<BoundSelectItem>,
    pub columns: Vec<BoundColumn>,
    pub selection: Option<Expr>,
    pub group_by: Vec<Expr>,
    pub having: Option<Expr>,
    pub order_by: Vec<OrderByExpr>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub applied_row_policies: Vec<String>,
    pub row_policy_predicates: Vec<BoundRowPolicy>,
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
    },
    AlterTableAddColumn {
        relation_id: RelationId,
        table: ObjectName,
        column: ColumnDef,
    },
    DropTable {
        relation_id: Option<RelationId>,
        name: ObjectName,
        if_exists: bool,
    },
    CreateFunction {
        name: Ident,
        argument_types: Vec<SqlType>,
        return_type: SqlType,
    },
    CreateOperator {
        signature: OperatorSignature,
    },
    CreateRole {
        name: Ident,
    },
    CreatePolicy {
        name: Ident,
        relation_id: RelationId,
        predicate: String,
    },
    GrantTablePrivilege {
        role_id: RoleId,
        relation_id: RelationId,
        privilege: Privilege,
    },
    Insert {
        table: ObjectName,
        columns: Vec<BoundColumn>,
        values: Vec<Expr>,
    },
    Update(BoundUpdate),
    Delete(BoundDelete),
    Select(BoundSelect),
    Transaction {
        action: TransactionAction,
    },
    Explain {
        analyze: bool,
        statement: Box<BoundStatement>,
    },
}
