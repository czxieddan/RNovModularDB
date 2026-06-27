use rnmdb_catalog::Privilege;
use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_types::SqlType;

use crate::{
    ast::{
        Assignment, ColumnDef, Expr, Ident, ObjectName, OrderByExpr, RangeLiteralBounds,
        SelectItem, SortDirection, Statement, TransactionAction,
    },
    lexer::{Token, TokenKind, lex},
};

pub fn parse_statement(input: &str) -> Result<Statement> {
    let tokens = lex(input)?;
    let mut parser = Parser::new(tokens);
    let statement = parser.parse_statement()?;
    parser.consume_optional_semicolon();
    parser.expect_end()?;
    Ok(statement)
}

pub fn parse_expr(input: &str) -> Result<Expr> {
    let tokens = lex(input)?;
    let mut parser = Parser::new(tokens);
    let expr = parser.parse_expr()?;
    parser.expect_end()?;
    Ok(expr)
}

struct Parser {
    tokens: Vec<Token>,
    position: usize,
}

impl Parser {
    fn new(tokens: Vec<Token>) -> Self {
        Self {
            tokens,
            position: 0,
        }
    }

    fn parse_statement(&mut self) -> Result<Statement> {
        match self.peek_kind() {
            Some(TokenKind::Create) => self.parse_create(),
            Some(TokenKind::Alter) => self.parse_alter(),
            Some(TokenKind::Drop) => self.parse_drop(),
            Some(TokenKind::Grant) => self.parse_grant(),
            Some(TokenKind::Insert) => self.parse_insert(),
            Some(TokenKind::Update) => self.parse_update(),
            Some(TokenKind::Delete) => self.parse_delete(),
            Some(TokenKind::Select) => self.parse_select(),
            Some(TokenKind::Begin) => self.parse_transaction(TransactionAction::Begin),
            Some(TokenKind::Commit) => self.parse_transaction(TransactionAction::Commit),
            Some(TokenKind::Rollback) => self.parse_transaction(TransactionAction::Rollback),
            Some(TokenKind::Explain) => self.parse_explain(),
            Some(kind) => Err(self.error(format!("unexpected statement token {kind:?}"))),
            None => Err(self.error("empty statement")),
        }
    }

    fn parse_explain(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Explain)?;
        let analyze = self.consume_if(&TokenKind::Analyze);
        if matches!(self.peek_kind(), Some(TokenKind::Explain)) {
            return Err(self.error("nested EXPLAIN is not supported"));
        }
        Ok(Statement::Explain {
            analyze,
            statement: Box::new(self.parse_statement()?),
        })
    }

    fn parse_create(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Create)?;
        match self.peek_kind() {
            Some(TokenKind::Table) => self.parse_create_table_tail(),
            Some(TokenKind::Function) => self.parse_create_function_tail(),
            Some(TokenKind::OperatorKeyword) => self.parse_create_operator_tail(),
            Some(TokenKind::Role) => self.parse_create_role_tail(),
            Some(TokenKind::Policy) => self.parse_create_policy_tail(),
            Some(kind) => Err(self.error(format!("unexpected CREATE target {kind:?}"))),
            None => Err(self.error("expected CREATE target")),
        }
    }

    fn parse_create_table_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Table)?;
        let name = self.parse_object_name()?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let mut columns = Vec::new();
        loop {
            columns.push(self.parse_column_def()?);

            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }
        self.expect_keyword(TokenKind::RightParen)?;

        Ok(Statement::CreateTable { name, columns })
    }

    fn parse_alter(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Alter)?;
        self.expect_keyword(TokenKind::Table)?;
        let table = self.parse_object_name()?;
        self.expect_keyword(TokenKind::Add)?;
        self.expect_keyword(TokenKind::Column)?;
        let column = self.parse_column_def()?;
        Ok(Statement::AlterTableAddColumn { table, column })
    }

    fn parse_drop(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Drop)?;
        self.expect_keyword(TokenKind::Table)?;
        let if_exists = if self.consume_if(&TokenKind::If) {
            self.expect_keyword(TokenKind::Exists)?;
            true
        } else {
            false
        };
        let name = self.parse_object_name()?;
        Ok(Statement::DropTable { name, if_exists })
    }

    fn parse_column_def(&mut self) -> Result<ColumnDef> {
        let name = self.parse_ident()?;
        let data_type = self.parse_type()?;
        let mut nullable = true;
        let mut encrypted = false;

        loop {
            match self.peek_kind() {
                Some(TokenKind::Not) => {
                    self.bump();
                    self.expect_keyword(TokenKind::Null)?;
                    nullable = false;
                }
                Some(TokenKind::Encrypted) => {
                    self.bump();
                    encrypted = true;
                }
                _ => break,
            }
        }

        Ok(ColumnDef {
            name,
            data_type,
            nullable,
            encrypted,
        })
    }

    fn parse_create_function_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Function)?;
        let name = self.parse_ident()?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let argument_types = if self.consume_if(&TokenKind::RightParen) {
            Vec::new()
        } else {
            let types = self.parse_type_list()?;
            self.expect_keyword(TokenKind::RightParen)?;
            types
        };
        self.expect_keyword(TokenKind::Returns)?;
        let return_type = self.parse_type()?;
        Ok(Statement::CreateFunction {
            name,
            argument_types,
            return_type,
        })
    }

    fn parse_create_operator_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::OperatorKeyword)?;
        let symbol = self.parse_operator_symbol()?;
        self.expect_keyword(TokenKind::LeftParen)?;
        self.expect_option_label("leftarg")?;
        self.expect_operator("=")?;
        let left_type = self.parse_type()?;
        self.expect_keyword(TokenKind::Comma)?;
        self.expect_option_label("rightarg")?;
        self.expect_operator("=")?;
        let right_type = self.parse_type()?;
        self.expect_keyword(TokenKind::Comma)?;
        self.expect_keyword(TokenKind::Returns)?;
        self.expect_operator("=")?;
        let result_type = self.parse_type()?;
        self.expect_keyword(TokenKind::Comma)?;
        self.expect_keyword(TokenKind::Function)?;
        self.expect_operator("=")?;
        let function = self.parse_ident()?;
        self.expect_keyword(TokenKind::RightParen)?;
        Ok(Statement::CreateOperator {
            symbol,
            left_type,
            right_type,
            result_type,
            function,
        })
    }

    fn parse_create_role_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Role)?;
        Ok(Statement::CreateRole {
            name: self.parse_ident()?,
        })
    }

    fn parse_create_policy_tail(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Policy)?;
        let name = self.parse_ident()?;
        self.expect_keyword(TokenKind::On)?;
        let table = self.parse_object_name()?;
        self.expect_keyword(TokenKind::Using)?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let predicate = self.parse_expr()?;
        self.expect_keyword(TokenKind::RightParen)?;
        Ok(Statement::CreatePolicy {
            name,
            table,
            predicate,
        })
    }

    fn parse_grant(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Grant)?;
        let privilege = self.parse_privilege()?;
        self.expect_keyword(TokenKind::On)?;
        self.expect_keyword(TokenKind::Table)?;
        let table = self.parse_object_name()?;
        self.expect_keyword(TokenKind::To)?;
        let role = self.parse_ident()?;
        Ok(Statement::GrantTablePrivilege {
            privilege,
            table,
            role,
        })
    }

    fn parse_insert(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Insert)?;
        self.expect_keyword(TokenKind::Into)?;
        let table = self.parse_object_name()?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let columns = self.parse_ident_list()?;
        self.expect_keyword(TokenKind::RightParen)?;
        self.expect_keyword(TokenKind::Values)?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let values = self.parse_expr_list()?;
        self.expect_keyword(TokenKind::RightParen)?;
        if columns.len() != values.len() {
            return Err(self.error("insert column count does not match value count"));
        }
        Ok(Statement::Insert {
            table,
            columns,
            values,
        })
    }

    fn parse_update(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Update)?;
        let table = self.parse_object_name()?;
        self.expect_keyword(TokenKind::Set)?;
        let assignments = self.parse_assignment_list()?;
        let selection = if self.consume_if(&TokenKind::Where) {
            Some(self.parse_expr()?)
        } else {
            None
        };
        Ok(Statement::Update {
            table,
            assignments,
            selection,
        })
    }

    fn parse_delete(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Delete)?;
        self.expect_keyword(TokenKind::From)?;
        let table = self.parse_object_name()?;
        let selection = if self.consume_if(&TokenKind::Where) {
            Some(self.parse_expr()?)
        } else {
            None
        };
        Ok(Statement::Delete { table, selection })
    }

    fn parse_transaction(&mut self, action: TransactionAction) -> Result<Statement> {
        self.bump();
        Ok(Statement::Transaction { action })
    }

    fn parse_select(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Select)?;
        let distinct = self.consume_if(&TokenKind::Distinct);
        let mut projection = Vec::new();
        loop {
            if self.consume_if(&TokenKind::Star) {
                projection.push(SelectItem::Wildcard);
            } else {
                let expr = self.parse_expr()?;
                let alias = if self.consume_if(&TokenKind::As) {
                    Some(self.parse_ident()?)
                } else {
                    None
                };
                projection.push(SelectItem::Expr { expr, alias });
            }
            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }
        self.expect_keyword(TokenKind::From)?;
        let from = self.parse_object_name()?;
        let selection = if self.consume_if(&TokenKind::Where) {
            Some(self.parse_expr()?)
        } else {
            None
        };
        let group_by = if self.consume_if(&TokenKind::Group) {
            self.expect_keyword(TokenKind::By)?;
            self.parse_expr_list()?
        } else {
            Vec::new()
        };
        let having = if self.consume_if(&TokenKind::Having) {
            Some(self.parse_expr()?)
        } else {
            None
        };
        let order_by = if self.consume_if(&TokenKind::Order) {
            self.expect_keyword(TokenKind::By)?;
            self.parse_order_by_list()?
        } else {
            Vec::new()
        };
        let limit = if self.consume_if(&TokenKind::Limit) {
            Some(self.parse_row_count("LIMIT")?)
        } else {
            None
        };
        let offset = if self.consume_if(&TokenKind::Offset) {
            Some(self.parse_row_count("OFFSET")?)
        } else {
            None
        };
        Ok(Statement::Select {
            distinct,
            projection,
            from,
            selection,
            group_by,
            having,
            order_by,
            limit,
            offset,
        })
    }

    fn parse_object_name(&mut self) -> Result<ObjectName> {
        let first = self.parse_ident()?;
        self.parse_object_name_from_first(first)
    }

    fn parse_object_name_from_first(&mut self, first: Ident) -> Result<ObjectName> {
        if self.consume_if(&TokenKind::Dot) {
            let second = self.parse_ident()?;
            Ok(ObjectName::qualified(first.as_str(), second.as_str()))
        } else {
            Ok(ObjectName::unqualified(first.as_str()))
        }
    }

    fn parse_ident_list(&mut self) -> Result<Vec<Ident>> {
        let mut identifiers = Vec::new();
        loop {
            identifiers.push(self.parse_ident()?);
            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }
        Ok(identifiers)
    }

    fn parse_expr_list(&mut self) -> Result<Vec<Expr>> {
        let mut expressions = Vec::new();
        loop {
            expressions.push(self.parse_expr()?);
            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }
        Ok(expressions)
    }

    fn parse_assignment_list(&mut self) -> Result<Vec<Assignment>> {
        let mut assignments = Vec::new();
        loop {
            let column = self.parse_ident()?;
            self.expect_operator("=")?;
            let value = self.parse_expr()?;
            assignments.push(Assignment { column, value });
            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }
        Ok(assignments)
    }

    fn parse_type_list(&mut self) -> Result<Vec<SqlType>> {
        let mut types = Vec::new();
        loop {
            types.push(self.parse_type()?);
            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }
        Ok(types)
    }

    fn parse_expr(&mut self) -> Result<Expr> {
        self.parse_or_expr()
    }

    fn parse_or_expr(&mut self) -> Result<Expr> {
        let mut expr = self.parse_and_expr()?;
        while self.consume_if(&TokenKind::Or) {
            let right = self.parse_and_expr()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op: "OR".to_string(),
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn parse_and_expr(&mut self) -> Result<Expr> {
        let mut expr = self.parse_not_expr()?;
        while self.consume_if(&TokenKind::And) {
            let right = self.parse_not_expr()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op: "AND".to_string(),
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn parse_not_expr(&mut self) -> Result<Expr> {
        if self.consume_if(&TokenKind::Not) {
            return Ok(Expr::Not(Box::new(self.parse_not_expr()?)));
        }
        self.parse_comparison_expr()
    }

    fn parse_comparison_expr(&mut self) -> Result<Expr> {
        let mut expr = self.parse_primary_expr()?;
        if self.consume_if(&TokenKind::Is) {
            let negated = self.consume_if(&TokenKind::Not);
            self.expect_keyword(TokenKind::Null)?;
            return Ok(Expr::IsNull {
                expr: Box::new(expr),
                negated,
            });
        }
        if self.consume_if(&TokenKind::Between) {
            return self.parse_between_tail(expr, false);
        }
        if self.consume_if(&TokenKind::Not) {
            self.expect_keyword(TokenKind::Between)?;
            return self.parse_between_tail(expr, true);
        }
        if let Some(TokenKind::Operator(op)) = self.peek_kind().cloned() {
            self.bump();
            let right = self.parse_primary_expr()?;
            expr = Expr::Binary {
                left: Box::new(expr),
                op,
                right: Box::new(right),
            };
        }
        Ok(expr)
    }

    fn parse_between_tail(&mut self, expr: Expr, negated: bool) -> Result<Expr> {
        let low = self.parse_primary_expr()?;
        self.expect_keyword(TokenKind::And)?;
        let high = self.parse_primary_expr()?;
        Ok(Expr::Between {
            expr: Box::new(expr),
            low: Box::new(low),
            high: Box::new(high),
            negated,
        })
    }

    fn parse_primary_expr(&mut self) -> Result<Expr> {
        match self.peek_kind().cloned() {
            Some(TokenKind::Identifier(_)) => {
                let first = self.parse_ident()?;
                if first.as_str() == "array" && self.consume_if(&TokenKind::LeftBracket) {
                    let values = if self.consume_if(&TokenKind::RightBracket) {
                        Vec::new()
                    } else {
                        let values = self.parse_expr_list()?;
                        self.expect_keyword(TokenKind::RightBracket)?;
                        values
                    };
                    return Ok(Expr::Array(values));
                }
                if first.as_str() == "hstore" && self.consume_if(&TokenKind::LeftParen) {
                    return self.parse_hstore_literal_tail();
                }
                if first.as_str() == "range" && self.consume_if(&TokenKind::LeftParen) {
                    return self.parse_range_literal_tail();
                }

                let name = self.parse_object_name_from_first(first)?;
                if self.consume_if(&TokenKind::LeftParen) {
                    if name.schema().is_none()
                        && name.object() == "count"
                        && self.consume_if(&TokenKind::Star)
                    {
                        self.expect_keyword(TokenKind::RightParen)?;
                        return Ok(Expr::CountStar);
                    }
                    let args = if self.consume_if(&TokenKind::RightParen) {
                        Vec::new()
                    } else {
                        let args = self.parse_expr_list()?;
                        self.expect_keyword(TokenKind::RightParen)?;
                        args
                    };
                    if name.schema().is_none() && name.object() == "count" {
                        let mut args = args;
                        return Ok(Expr::Count(Box::new(
                            self.single_function_arg("count", &mut args)?,
                        )));
                    }
                    if name.schema().is_none() && name.object() == "sum" {
                        let mut args = args;
                        return Ok(Expr::Sum(Box::new(
                            self.single_function_arg("sum", &mut args)?,
                        )));
                    }
                    if name.schema().is_none() && name.object() == "min" {
                        let mut args = args;
                        return Ok(Expr::Min(Box::new(
                            self.single_function_arg("min", &mut args)?,
                        )));
                    }
                    if name.schema().is_none() && name.object() == "max" {
                        let mut args = args;
                        return Ok(Expr::Max(Box::new(
                            self.single_function_arg("max", &mut args)?,
                        )));
                    }
                    Ok(Expr::Call { name, args })
                } else if name.schema().is_none() {
                    Ok(Expr::Identifier(Ident::new(name.object())))
                } else {
                    Ok(Expr::Identifier(Ident::new(name.object())))
                }
            }
            Some(TokenKind::Integer(value)) => {
                self.bump();
                Ok(Expr::Integer(value))
            }
            Some(TokenKind::String(value)) => {
                self.bump();
                Ok(Expr::String(value))
            }
            Some(TokenKind::Null) => {
                self.bump();
                Ok(Expr::Null)
            }
            Some(TokenKind::LeftParen) => {
                self.bump();
                let expr = self.parse_expr()?;
                self.expect_keyword(TokenKind::RightParen)?;
                Ok(expr)
            }
            Some(kind) => Err(self.error(format!("unexpected expression token {kind:?}"))),
            None => Err(self.error("expected expression")),
        }
    }

    fn parse_hstore_literal_tail(&mut self) -> Result<Expr> {
        let mut entries = Vec::new();
        if self.consume_if(&TokenKind::RightParen) {
            return Ok(Expr::HStore(entries));
        }

        loop {
            let key = self.parse_string_literal("hstore key")?;
            self.expect_operator("=>")?;
            let value = if self.consume_if(&TokenKind::Null) {
                None
            } else {
                Some(self.parse_string_literal("hstore value")?)
            };
            entries.push((key, value));

            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }

        self.expect_keyword(TokenKind::RightParen)?;
        Ok(Expr::HStore(entries))
    }

    fn parse_range_literal_tail(&mut self) -> Result<Expr> {
        let lower = self.parse_expr()?;
        self.expect_keyword(TokenKind::Comma)?;
        let upper = self.parse_expr()?;
        self.expect_keyword(TokenKind::Comma)?;
        let raw_bounds = self.parse_string_literal("range bounds")?;
        let bounds = RangeLiteralBounds::parse(&raw_bounds)
            .ok_or_else(|| self.error("range bounds must be one of [], [), (], ()"))?;
        self.expect_keyword(TokenKind::RightParen)?;
        Ok(Expr::Range {
            lower: Box::new(lower),
            upper: Box::new(upper),
            bounds,
        })
    }

    fn parse_type(&mut self) -> Result<SqlType> {
        let type_name = self.parse_ident()?;
        let mut data_type = if type_name.as_str() == "range" {
            self.expect_operator("<")?;
            let element_type = self.parse_type()?;
            self.expect_operator(">")?;
            SqlType::Range(Box::new(element_type))
        } else {
            match type_name.as_str() {
                "bool" | "boolean" => SqlType::Bool,
                "int64" | "bigint" | "integer" => SqlType::Int64,
                "uint64" => SqlType::UInt64,
                "text" | "string" | "varchar" => SqlType::Text,
                "bytes" | "bytea" => SqlType::Bytes,
                "hstore" => SqlType::HStore,
                "textvector" | "tsvector" => SqlType::TextVector,
                unknown => return Err(self.error(format!("unknown SQL type {unknown}"))),
            }
        };

        while self.consume_if(&TokenKind::LeftBracket) {
            self.expect_keyword(TokenKind::RightBracket)?;
            data_type = SqlType::Array(Box::new(data_type));
        }

        Ok(data_type)
    }

    fn parse_string_literal(&mut self, name: &'static str) -> Result<String> {
        match self.peek_kind().cloned() {
            Some(TokenKind::String(value)) => {
                self.bump();
                Ok(value)
            }
            Some(kind) => Err(self.error(format!("expected {name} but found {kind:?}"))),
            None => Err(self.error(format!("expected {name}"))),
        }
    }

    fn parse_order_by_list(&mut self) -> Result<Vec<OrderByExpr>> {
        let mut expressions = Vec::new();
        loop {
            let expr = self.parse_expr()?;
            let direction = if self.consume_if(&TokenKind::Desc) {
                SortDirection::Desc
            } else {
                let _ = self.consume_if(&TokenKind::Asc);
                SortDirection::Asc
            };
            expressions.push(OrderByExpr { expr, direction });
            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }
        Ok(expressions)
    }

    fn parse_row_count(&mut self, clause: &'static str) -> Result<usize> {
        match self.peek_kind().cloned() {
            Some(TokenKind::Integer(value)) => {
                self.bump();
                usize::try_from(value)
                    .map_err(|_| self.error(format!("{clause} must be a non-negative integer")))
            }
            Some(kind) => Err(self.error(format!("expected {clause} value but found {kind:?}"))),
            None => Err(self.error(format!("expected {clause} value"))),
        }
    }

    fn parse_privilege(&mut self) -> Result<Privilege> {
        match self.peek_kind() {
            Some(TokenKind::Select) => {
                self.bump();
                Ok(Privilege::Select)
            }
            Some(TokenKind::Insert) => {
                self.bump();
                Ok(Privilege::Insert)
            }
            Some(TokenKind::Update) => {
                self.bump();
                Ok(Privilege::Update)
            }
            Some(TokenKind::Delete) => {
                self.bump();
                Ok(Privilege::Delete)
            }
            Some(TokenKind::Execute) => {
                self.bump();
                Ok(Privilege::Execute)
            }
            Some(kind) => Err(self.error(format!("expected privilege but found {kind:?}"))),
            None => Err(self.error("expected privilege")),
        }
    }

    fn single_function_arg(&self, name: &'static str, args: &mut Vec<Expr>) -> Result<Expr> {
        if args.len() != 1 {
            return Err(self.error(format!("{name}() requires exactly one expression")));
        }
        Ok(args.remove(0))
    }

    fn parse_operator_symbol(&mut self) -> Result<String> {
        match self.peek_kind().cloned() {
            Some(TokenKind::Operator(symbol)) => {
                self.bump();
                Ok(symbol)
            }
            Some(TokenKind::Identifier(symbol)) => {
                self.bump();
                Ok(symbol)
            }
            Some(kind) => Err(self.error(format!("expected operator symbol but found {kind:?}"))),
            None => Err(self.error("expected operator symbol")),
        }
    }

    fn expect_operator(&mut self, expected: &str) -> Result<()> {
        match self.peek_kind().cloned() {
            Some(TokenKind::Operator(op)) if op == expected => {
                self.bump();
                Ok(())
            }
            Some(kind) => {
                Err(self.error(format!("expected operator {expected} but found {kind:?}")))
            }
            None => Err(self.error(format!("expected operator {expected}"))),
        }
    }

    fn expect_option_label(&mut self, expected: &str) -> Result<()> {
        let ident = self.parse_ident()?;
        if ident.as_str() == expected {
            Ok(())
        } else {
            Err(self.error(format!("expected option {expected}")))
        }
    }

    fn parse_ident(&mut self) -> Result<Ident> {
        match self.peek_kind().cloned() {
            Some(TokenKind::Identifier(value)) => {
                self.bump();
                Ok(Ident::new(value))
            }
            Some(kind) => Err(self.error(format!("expected identifier but found {kind:?}"))),
            None => Err(self.error("expected identifier")),
        }
    }

    fn expect_keyword(&mut self, expected: TokenKind) -> Result<()> {
        if self.consume_if(&expected) {
            Ok(())
        } else {
            Err(self.error(format!("expected {expected:?}")))
        }
    }

    fn consume_optional_semicolon(&mut self) {
        let _ = self.consume_if(&TokenKind::Semicolon);
    }

    fn expect_end(&self) -> Result<()> {
        if self.position == self.tokens.len() {
            Ok(())
        } else {
            Err(self.error("unexpected trailing tokens"))
        }
    }

    fn consume_if(&mut self, expected: &TokenKind) -> bool {
        let Some(actual) = self.peek_kind() else {
            return false;
        };
        if same_token_variant(actual, expected) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn bump(&mut self) {
        self.position += 1;
    }

    fn peek_kind(&self) -> Option<&TokenKind> {
        self.tokens.get(self.position).map(Token::kind)
    }

    fn error(&self, message: impl Into<String>) -> RnovError {
        RnovError::new(ErrorKind::InvalidInput, message)
    }
}

fn same_token_variant(left: &TokenKind, right: &TokenKind) -> bool {
    matches!(
        (left, right),
        (TokenKind::Select, TokenKind::Select)
            | (TokenKind::Distinct, TokenKind::Distinct)
            | (TokenKind::As, TokenKind::As)
            | (TokenKind::Insert, TokenKind::Insert)
            | (TokenKind::Into, TokenKind::Into)
            | (TokenKind::Values, TokenKind::Values)
            | (TokenKind::Update, TokenKind::Update)
            | (TokenKind::Delete, TokenKind::Delete)
            | (TokenKind::Set, TokenKind::Set)
            | (TokenKind::Create, TokenKind::Create)
            | (TokenKind::Alter, TokenKind::Alter)
            | (TokenKind::Drop, TokenKind::Drop)
            | (TokenKind::Add, TokenKind::Add)
            | (TokenKind::Column, TokenKind::Column)
            | (TokenKind::If, TokenKind::If)
            | (TokenKind::Exists, TokenKind::Exists)
            | (TokenKind::Table, TokenKind::Table)
            | (TokenKind::From, TokenKind::From)
            | (TokenKind::Where, TokenKind::Where)
            | (TokenKind::Group, TokenKind::Group)
            | (TokenKind::Having, TokenKind::Having)
            | (TokenKind::Order, TokenKind::Order)
            | (TokenKind::By, TokenKind::By)
            | (TokenKind::Asc, TokenKind::Asc)
            | (TokenKind::Desc, TokenKind::Desc)
            | (TokenKind::Limit, TokenKind::Limit)
            | (TokenKind::Offset, TokenKind::Offset)
            | (TokenKind::Function, TokenKind::Function)
            | (TokenKind::Returns, TokenKind::Returns)
            | (TokenKind::OperatorKeyword, TokenKind::OperatorKeyword)
            | (TokenKind::Role, TokenKind::Role)
            | (TokenKind::Grant, TokenKind::Grant)
            | (TokenKind::On, TokenKind::On)
            | (TokenKind::To, TokenKind::To)
            | (TokenKind::Policy, TokenKind::Policy)
            | (TokenKind::Using, TokenKind::Using)
            | (TokenKind::Execute, TokenKind::Execute)
            | (TokenKind::Begin, TokenKind::Begin)
            | (TokenKind::Commit, TokenKind::Commit)
            | (TokenKind::Rollback, TokenKind::Rollback)
            | (TokenKind::And, TokenKind::And)
            | (TokenKind::Or, TokenKind::Or)
            | (TokenKind::Not, TokenKind::Not)
            | (TokenKind::Is, TokenKind::Is)
            | (TokenKind::Between, TokenKind::Between)
            | (TokenKind::Null, TokenKind::Null)
            | (TokenKind::Encrypted, TokenKind::Encrypted)
            | (TokenKind::Explain, TokenKind::Explain)
            | (TokenKind::Analyze, TokenKind::Analyze)
            | (TokenKind::Comma, TokenKind::Comma)
            | (TokenKind::Dot, TokenKind::Dot)
            | (TokenKind::Semicolon, TokenKind::Semicolon)
            | (TokenKind::Star, TokenKind::Star)
            | (TokenKind::LeftParen, TokenKind::LeftParen)
            | (TokenKind::RightParen, TokenKind::RightParen)
            | (TokenKind::LeftBracket, TokenKind::LeftBracket)
            | (TokenKind::RightBracket, TokenKind::RightBracket)
    )
}
