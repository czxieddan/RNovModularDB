use rnovdb_common::{ErrorKind, Result, RnovError};
use rnovdb_types::SqlType;

use crate::{
    ast::{ColumnDef, Expr, Ident, ObjectName, SelectItem, Statement},
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
            Some(TokenKind::Create) => self.parse_create_table(),
            Some(TokenKind::Insert) => self.parse_insert(),
            Some(TokenKind::Select) => self.parse_select(),
            Some(kind) => Err(self.error(format!("unexpected statement token {kind:?}"))),
            None => Err(self.error("empty statement")),
        }
    }

    fn parse_create_table(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Create)?;
        self.expect_keyword(TokenKind::Table)?;
        let name = self.parse_object_name()?;
        self.expect_keyword(TokenKind::LeftParen)?;
        let mut columns = Vec::new();
        loop {
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

            columns.push(ColumnDef {
                name,
                data_type,
                nullable,
                encrypted,
            });

            if self.consume_if(&TokenKind::Comma) {
                continue;
            }
            break;
        }
        self.expect_keyword(TokenKind::RightParen)?;

        Ok(Statement::CreateTable { name, columns })
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

    fn parse_select(&mut self) -> Result<Statement> {
        self.expect_keyword(TokenKind::Select)?;
        let mut projection = Vec::new();
        loop {
            if self.consume_if(&TokenKind::Star) {
                projection.push(SelectItem::Wildcard);
            } else {
                projection.push(SelectItem::Expr(self.parse_expr()?));
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
        Ok(Statement::Select {
            projection,
            from,
            selection,
        })
    }

    fn parse_object_name(&mut self) -> Result<ObjectName> {
        let first = self.parse_ident()?;
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

    fn parse_expr(&mut self) -> Result<Expr> {
        let mut expr = self.parse_primary_expr()?;
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

    fn parse_primary_expr(&mut self) -> Result<Expr> {
        match self.peek_kind().cloned() {
            Some(TokenKind::Identifier(_)) => {
                let name = self.parse_object_name()?;
                if self.consume_if(&TokenKind::LeftParen) {
                    let args = if self.consume_if(&TokenKind::RightParen) {
                        Vec::new()
                    } else {
                        let args = self.parse_expr_list()?;
                        self.expect_keyword(TokenKind::RightParen)?;
                        args
                    };
                    Ok(Expr::Call { name, args })
                } else if name.schema().is_none() {
                    Ok(Expr::Identifier(Ident::new(name.object())))
                } else {
                    Err(self.error("qualified identifiers are not supported in expressions yet"))
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
            Some(kind) => Err(self.error(format!("unexpected expression token {kind:?}"))),
            None => Err(self.error("expected expression")),
        }
    }

    fn parse_type(&mut self) -> Result<SqlType> {
        let type_name = self.parse_ident()?;
        let mut data_type = match type_name.as_str() {
            "bool" | "boolean" => SqlType::Bool,
            "int64" | "bigint" | "integer" => SqlType::Int64,
            "uint64" => SqlType::UInt64,
            "text" | "string" | "varchar" => SqlType::Text,
            "bytes" | "bytea" => SqlType::Bytes,
            "hstore" => SqlType::HStore,
            "textvector" | "tsvector" => SqlType::TextVector,
            unknown => return Err(self.error(format!("unknown SQL type {unknown}"))),
        };

        while self.consume_if(&TokenKind::LeftBracket) {
            self.expect_keyword(TokenKind::RightBracket)?;
            data_type = SqlType::Array(Box::new(data_type));
        }

        Ok(data_type)
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
            | (TokenKind::Insert, TokenKind::Insert)
            | (TokenKind::Into, TokenKind::Into)
            | (TokenKind::Values, TokenKind::Values)
            | (TokenKind::Create, TokenKind::Create)
            | (TokenKind::Table, TokenKind::Table)
            | (TokenKind::From, TokenKind::From)
            | (TokenKind::Where, TokenKind::Where)
            | (TokenKind::Not, TokenKind::Not)
            | (TokenKind::Null, TokenKind::Null)
            | (TokenKind::Encrypted, TokenKind::Encrypted)
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
