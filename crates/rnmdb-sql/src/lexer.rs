// crates/rnmdb-sql/src/lexer.rs - RNovModularDB source module.
// Copyright (C) 2026 czxieddan
//
// The AHCL-covered material identified below forms part of
// RNovModularDB and is provided under version 1.2 of the
// Aperip Heimdall Commons License (AHCL). The applicable version is also subject
// to the AHCL provisions concerning Continuous AHCL Licensing Segments and
// migration to later official versions.
//
// AHCL-covered portions: the whole file
//
// Subject to Section 3.1 of AHCL, after having a reasonable opportunity to
// read AHCL, all applicable Additional Restrictions, and all version notices,
// a person accepts the corresponding terms by engaging in Use of the
// AHCL-covered material identified above. Any separate or affirmative assent
// required by applicable mandatory law must still be obtained.
//
// License notice updated: October 15, 2026.
// Official AHCL text and public notices: https://ahcl.aperip.com
// Applicable LICENSE: LICENSE
// Paths below are relative to the directory containing that LICENSE.
// AHCL Materials Directory: .ahcl/
// Repository official or recognized AHCL copy: .ahcl/AHCL-1.2.md
// Canonical repository: https://github.com/czxieddan/RNovModularDB
// Project notice: .ahcl/AHCL-PROJECT-NOTICE.md
// Version records: .ahcl/AHCL-VERSION-ADOPTION.md
// Source and history: .ahcl/AHCL-SOURCE.md
// Dependencies and licenses: .ahcl/AHCL-DEPENDENCIES.md
// Additional Restrictions: None.
// SPDX-License-Identifier: LicenseRef-AHCL-1.2
use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_types::SqlFloat64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenKind {
    Select,
    Union,
    Intersect,
    Except,
    With,
    Recursive,
    Distinct,
    All,
    As,
    Insert,
    Into,
    Values,
    Update,
    Delete,
    Set,
    Create,
    Trigger,
    Index,
    Unique,
    Alter,
    Drop,
    Add,
    Column,
    If,
    Exists,
    Table,
    After,
    From,
    Join,
    Inner,
    Left,
    Outer,
    Lateral,
    Where,
    Group,
    Grouping,
    Sets,
    Rollup,
    Cube,
    Over,
    Having,
    Order,
    By,
    Asc,
    Desc,
    Nulls,
    First,
    Last,
    Limit,
    Offset,
    Fetch,
    Next,
    Row,
    Rows,
    Only,
    Function,
    Procedure,
    Returns,
    OperatorKeyword,
    Role,
    Grant,
    On,
    To,
    Policy,
    Using,
    Execute,
    Call,
    Begin,
    Commit,
    Rollback,
    And,
    Or,
    Not,
    Case,
    When,
    Then,
    Else,
    End,
    Is,
    Between,
    In,
    Like,
    Null,
    True,
    False,
    Unknown,
    Encrypted,
    References,
    Generated,
    Always,
    Stored,
    Explain,
    Analyze,
    Identifier(String),
    Integer(i64),
    Float64(SqlFloat64),
    String(String),
    Operator(String),
    Comma,
    Dot,
    Semicolon,
    Star,
    LeftParen,
    RightParen,
    LeftBracket,
    RightBracket,
}
static KEYWORDS: phf::Map<&'static str, TokenKind> = phf::phf_map! {
    "select" => TokenKind::Select,
    "union" => TokenKind::Union,
    "intersect" => TokenKind::Intersect,
    "except" => TokenKind::Except,
    "with" => TokenKind::With,
    "recursive" => TokenKind::Recursive,
    "distinct" => TokenKind::Distinct,
    "all" => TokenKind::All,
    "as" => TokenKind::As,
    "insert" => TokenKind::Insert,
    "into" => TokenKind::Into,
    "values" => TokenKind::Values,
    "update" => TokenKind::Update,
    "delete" => TokenKind::Delete,
    "set" => TokenKind::Set,
    "create" => TokenKind::Create,
    "trigger" => TokenKind::Trigger,
    "index" => TokenKind::Index,
    "unique" => TokenKind::Unique,
    "alter" => TokenKind::Alter,
    "drop" => TokenKind::Drop,
    "add" => TokenKind::Add,
    "column" => TokenKind::Column,
    "if" => TokenKind::If,
    "exists" => TokenKind::Exists,
    "table" => TokenKind::Table,
    "after" => TokenKind::After,
    "from" => TokenKind::From,
    "join" => TokenKind::Join,
    "inner" => TokenKind::Inner,
    "left" => TokenKind::Left,
    "outer" => TokenKind::Outer,
    "lateral" => TokenKind::Lateral,
    "where" => TokenKind::Where,
    "group" => TokenKind::Group,
    "grouping" => TokenKind::Grouping,
    "sets" => TokenKind::Sets,
    "rollup" => TokenKind::Rollup,
    "cube" => TokenKind::Cube,
    "over" => TokenKind::Over,
    "having" => TokenKind::Having,
    "order" => TokenKind::Order,
    "by" => TokenKind::By,
    "asc" => TokenKind::Asc,
    "desc" => TokenKind::Desc,
    "nulls" => TokenKind::Nulls,
    "first" => TokenKind::First,
    "last" => TokenKind::Last,
    "limit" => TokenKind::Limit,
    "offset" => TokenKind::Offset,
    "fetch" => TokenKind::Fetch,
    "next" => TokenKind::Next,
    "row" => TokenKind::Row,
    "rows" => TokenKind::Rows,
    "only" => TokenKind::Only,
    "function" => TokenKind::Function,
    "procedure" => TokenKind::Procedure,
    "returns" => TokenKind::Returns,
    "operator" => TokenKind::OperatorKeyword,
    "role" => TokenKind::Role,
    "grant" => TokenKind::Grant,
    "on" => TokenKind::On,
    "to" => TokenKind::To,
    "policy" => TokenKind::Policy,
    "using" => TokenKind::Using,
    "execute" => TokenKind::Execute,
    "call" => TokenKind::Call,
    "begin" => TokenKind::Begin,
    "commit" => TokenKind::Commit,
    "rollback" => TokenKind::Rollback,
    "and" => TokenKind::And,
    "or" => TokenKind::Or,
    "not" => TokenKind::Not,
    "case" => TokenKind::Case,
    "when" => TokenKind::When,
    "then" => TokenKind::Then,
    "else" => TokenKind::Else,
    "end" => TokenKind::End,
    "is" => TokenKind::Is,
    "between" => TokenKind::Between,
    "in" => TokenKind::In,
    "like" => TokenKind::Like,
    "null" => TokenKind::Null,
    "true" => TokenKind::True,
    "false" => TokenKind::False,
    "unknown" => TokenKind::Unknown,
    "encrypted" => TokenKind::Encrypted,
    "references" => TokenKind::References,
    "generated" => TokenKind::Generated,
    "always" => TokenKind::Always,
    "stored" => TokenKind::Stored,
    "explain" => TokenKind::Explain,
    "analyze" => TokenKind::Analyze,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Token {
    kind: TokenKind,
    span: Span,
}

impl Token {
    fn new(kind: TokenKind, start: usize, end: usize) -> Self {
        Self {
            kind,
            span: Span { start, end },
        }
    }

    pub fn kind(&self) -> &TokenKind {
        &self.kind
    }

    pub fn span(&self) -> Span {
        self.span
    }
}

pub fn lex(input: &str) -> Result<Vec<Token>> {
    Lexer::new(input).lex()
}

struct Lexer<'a> {
    input: &'a str,
    position: usize,
}

impl<'a> Lexer<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, position: 0 }
    }

    fn lex(mut self) -> Result<Vec<Token>> {
        let mut tokens = Vec::new();
        while let Some(byte) = self.peek_byte() {
            let start = self.position;
            match byte {
                b' ' | b'\t' | b'\r' | b'\n' => {
                    self.position += 1;
                }
                b',' => tokens.push(self.take_single(TokenKind::Comma)),
                b'.' => tokens.push(self.take_single(TokenKind::Dot)),
                b';' => tokens.push(self.take_single(TokenKind::Semicolon)),
                b'*' => tokens.push(self.take_single(TokenKind::Star)),
                b'(' => tokens.push(self.take_single(TokenKind::LeftParen)),
                b')' => tokens.push(self.take_single(TokenKind::RightParen)),
                b'[' => tokens.push(self.take_single(TokenKind::LeftBracket)),
                b']' => tokens.push(self.take_single(TokenKind::RightBracket)),
                b'\'' => tokens.push(self.lex_string()?),
                b'0'..=b'9' => tokens.push(self.lex_number()?),
                b'-' if self.peek_next_byte() == Some(b'-') => self.skip_line_comment(),
                b'/' if self.peek_next_byte() == Some(b'*') => self.skip_block_comment()?,
                _ if is_identifier_start(byte) => tokens.push(self.lex_identifier_or_keyword()),
                _ if is_operator_byte(byte) => tokens.push(self.lex_operator()),
                _ => {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        format!("unexpected byte 0x{byte:02x} at {start}"),
                    ));
                }
            }
        }
        Ok(tokens)
    }

    fn take_single(&mut self, kind: TokenKind) -> Token {
        let start = self.position;
        self.position += 1;
        Token::new(kind, start, self.position)
    }

    fn lex_identifier_or_keyword(&mut self) -> Token {
        let start = self.position;
        self.position += 1;
        while let Some(byte) = self.peek_byte() {
            if !is_identifier_continue(byte) {
                break;
            }
            self.position += 1;
        }
        let raw = &self.input[start..self.position];
        let normalized = raw.to_ascii_lowercase();
        let kind = KEYWORDS
            .get(normalized.as_str())
            .cloned()
            .unwrap_or(TokenKind::Identifier(normalized));
        Token::new(kind, start, self.position)
    }

    fn lex_number(&mut self) -> Result<Token> {
        let start = self.position;
        self.consume_digits();
        if self.should_lex_fraction() {
            self.position += 1;
            self.consume_digits();
            return self.float_token(start);
        }
        self.integer_token(start)
    }

    fn consume_digits(&mut self) {
        while self.peek_byte().is_some_and(|byte| byte.is_ascii_digit()) {
            self.position += 1;
        }
    }

    fn should_lex_fraction(&self) -> bool {
        self.peek_byte() == Some(b'.')
            && self
                .peek_byte_at(self.position + 1)
                .is_some_and(|byte| byte.is_ascii_digit())
    }

    fn integer_token(&self, start: usize) -> Result<Token> {
        let text = &self.input[start..self.position];
        let value = text.parse::<i64>().map_err(|_| {
            RnovError::new(
                ErrorKind::InvalidInput,
                format!("integer literal is out of range at {start}"),
            )
        })?;
        Ok(Token::new(TokenKind::Integer(value), start, self.position))
    }

    fn float_token(&self, start: usize) -> Result<Token> {
        let text = &self.input[start..self.position];
        let parsed = text.parse::<f64>().map_err(|_| {
            RnovError::new(
                ErrorKind::InvalidInput,
                format!("float64 literal is invalid at {start}"),
            )
        })?;
        let value = SqlFloat64::new(parsed)?;
        Ok(Token::new(TokenKind::Float64(value), start, self.position))
    }

    fn lex_string(&mut self) -> Result<Token> {
        let start = self.position;
        self.position += 1;
        let mut value = String::new();
        while let Some(byte) = self.peek_byte() {
            match byte {
                b'\'' => {
                    self.position += 1;
                    if self.peek_byte() == Some(b'\'') {
                        value.push('\'');
                        self.position += 1;
                        continue;
                    }
                    return Ok(Token::new(TokenKind::String(value), start, self.position));
                }
                _ => {
                    let ch = self.input[self.position..].chars().next().ok_or_else(|| {
                        RnovError::new(ErrorKind::InvalidInput, "unterminated string literal")
                    })?;
                    value.push(ch);
                    self.position += ch.len_utf8();
                }
            }
        }
        Err(RnovError::new(
            ErrorKind::InvalidInput,
            "unterminated string literal",
        ))
    }

    fn lex_operator(&mut self) -> Token {
        let start = self.position;
        while let Some(byte) = self.peek_byte() {
            if !is_operator_byte(byte) {
                break;
            }
            self.position += 1;
        }
        Token::new(
            TokenKind::Operator(self.input[start..self.position].to_string()),
            start,
            self.position,
        )
    }

    fn skip_line_comment(&mut self) {
        while let Some(byte) = self.peek_byte() {
            self.position += 1;
            if byte == b'\n' {
                break;
            }
        }
    }

    fn skip_block_comment(&mut self) -> Result<()> {
        let start = self.position;
        self.position += 2;
        let mut depth = 1_usize;
        while self.position < self.input.len() {
            match (self.peek_byte(), self.peek_next_byte()) {
                (Some(b'/'), Some(b'*')) => {
                    depth = depth.checked_add(1).ok_or_else(|| {
                        RnovError::new(ErrorKind::InvalidInput, "block comment nesting is too deep")
                    })?;
                    self.position += 2;
                }
                (Some(b'*'), Some(b'/')) => {
                    depth -= 1;
                    self.position += 2;
                    if depth == 0 {
                        return Ok(());
                    }
                }
                (Some(byte), _) if byte.is_ascii() => self.position += 1,
                (Some(_), _) => {
                    let ch = self.input[self.position..].chars().next().ok_or_else(|| {
                        RnovError::new(ErrorKind::InvalidInput, "unterminated block comment")
                    })?;
                    self.position += ch.len_utf8();
                }
                (None, _) => break,
            }
        }
        Err(RnovError::new(
            ErrorKind::InvalidInput,
            format!("unterminated block comment at {start}"),
        ))
    }

    fn peek_byte(&self) -> Option<u8> {
        self.input.as_bytes().get(self.position).copied()
    }

    fn peek_next_byte(&self) -> Option<u8> {
        self.peek_byte_at(self.position + 1)
    }

    fn peek_byte_at(&self, position: usize) -> Option<u8> {
        self.input.as_bytes().get(position).copied()
    }
}

fn is_identifier_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn is_identifier_continue(byte: u8) -> bool {
    byte == b'_' || byte == b'$' || byte.is_ascii_alphanumeric()
}

fn is_operator_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'=' | b'<'
            | b'>'
            | b'!'
            | b'+'
            | b'-'
            | b'/'
            | b'%'
            | b'@'
            | b'|'
            | b'&'
            | b'~'
            | b'#'
            | b'?'
    )
}
