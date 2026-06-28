use rnmdb_common::{ErrorKind, Result, RnovError};

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TokenKind {
    Select,
    Union,
    Intersect,
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
    Alter,
    Drop,
    Add,
    Column,
    If,
    Exists,
    Table,
    From,
    Where,
    Group,
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
    Returns,
    OperatorKeyword,
    Role,
    Grant,
    On,
    To,
    Policy,
    Using,
    Execute,
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
    Explain,
    Analyze,
    Identifier(String),
    Integer(i64),
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
                b'0'..=b'9' => tokens.push(self.lex_integer()?),
                b'-' if self.peek_next_byte() == Some(b'-') => self.skip_line_comment(),
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
        let kind = match normalized.as_str() {
            "select" => TokenKind::Select,
            "union" => TokenKind::Union,
            "intersect" => TokenKind::Intersect,
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
            "alter" => TokenKind::Alter,
            "drop" => TokenKind::Drop,
            "add" => TokenKind::Add,
            "column" => TokenKind::Column,
            "if" => TokenKind::If,
            "exists" => TokenKind::Exists,
            "table" => TokenKind::Table,
            "from" => TokenKind::From,
            "where" => TokenKind::Where,
            "group" => TokenKind::Group,
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
            "returns" => TokenKind::Returns,
            "operator" => TokenKind::OperatorKeyword,
            "role" => TokenKind::Role,
            "grant" => TokenKind::Grant,
            "on" => TokenKind::On,
            "to" => TokenKind::To,
            "policy" => TokenKind::Policy,
            "using" => TokenKind::Using,
            "execute" => TokenKind::Execute,
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
            "explain" => TokenKind::Explain,
            "analyze" => TokenKind::Analyze,
            _ => TokenKind::Identifier(normalized),
        };
        Token::new(kind, start, self.position)
    }

    fn lex_integer(&mut self) -> Result<Token> {
        let start = self.position;
        while let Some(byte @ b'0'..=b'9') = self.peek_byte() {
            let _ = byte;
            self.position += 1;
        }
        let text = &self.input[start..self.position];
        let value = text.parse::<i64>().map_err(|_| {
            RnovError::new(
                ErrorKind::InvalidInput,
                format!("integer literal is out of range at {start}"),
            )
        })?;
        Ok(Token::new(TokenKind::Integer(value), start, self.position))
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

    fn peek_byte(&self) -> Option<u8> {
        self.input.as_bytes().get(self.position).copied()
    }

    fn peek_next_byte(&self) -> Option<u8> {
        self.input.as_bytes().get(self.position + 1).copied()
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
