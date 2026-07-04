use rnmdb_common::{ErrorKind, Result, RnovError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeywordToken {
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
    Index,
    Unique,
    Alter,
    Drop,
    Add,
    Column,
    If,
    Exists,
    Table,
    From,
    Join,
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
    Generated,
    Always,
    Stored,
    Explain,
    Analyze,
}

impl From<KeywordToken> for TokenKind {
    fn from(keyword: KeywordToken) -> Self {
        match keyword {
            KeywordToken::Select => Self::Select,
            KeywordToken::Union => Self::Union,
            KeywordToken::Intersect => Self::Intersect,
            KeywordToken::Except => Self::Except,
            KeywordToken::With => Self::With,
            KeywordToken::Recursive => Self::Recursive,
            KeywordToken::Distinct => Self::Distinct,
            KeywordToken::All => Self::All,
            KeywordToken::As => Self::As,
            KeywordToken::Insert => Self::Insert,
            KeywordToken::Into => Self::Into,
            KeywordToken::Values => Self::Values,
            KeywordToken::Update => Self::Update,
            KeywordToken::Delete => Self::Delete,
            KeywordToken::Set => Self::Set,
            KeywordToken::Create => Self::Create,
            KeywordToken::Index => Self::Index,
            KeywordToken::Unique => Self::Unique,
            KeywordToken::Alter => Self::Alter,
            KeywordToken::Drop => Self::Drop,
            KeywordToken::Add => Self::Add,
            KeywordToken::Column => Self::Column,
            KeywordToken::If => Self::If,
            KeywordToken::Exists => Self::Exists,
            KeywordToken::Table => Self::Table,
            KeywordToken::From => Self::From,
            KeywordToken::Join => Self::Join,
            KeywordToken::Lateral => Self::Lateral,
            KeywordToken::Where => Self::Where,
            KeywordToken::Group => Self::Group,
            KeywordToken::Grouping => Self::Grouping,
            KeywordToken::Sets => Self::Sets,
            KeywordToken::Rollup => Self::Rollup,
            KeywordToken::Cube => Self::Cube,
            KeywordToken::Over => Self::Over,
            KeywordToken::Having => Self::Having,
            KeywordToken::Order => Self::Order,
            KeywordToken::By => Self::By,
            KeywordToken::Asc => Self::Asc,
            KeywordToken::Desc => Self::Desc,
            KeywordToken::Nulls => Self::Nulls,
            KeywordToken::First => Self::First,
            KeywordToken::Last => Self::Last,
            KeywordToken::Limit => Self::Limit,
            KeywordToken::Offset => Self::Offset,
            KeywordToken::Fetch => Self::Fetch,
            KeywordToken::Next => Self::Next,
            KeywordToken::Row => Self::Row,
            KeywordToken::Rows => Self::Rows,
            KeywordToken::Only => Self::Only,
            KeywordToken::Function => Self::Function,
            KeywordToken::Procedure => Self::Procedure,
            KeywordToken::Returns => Self::Returns,
            KeywordToken::OperatorKeyword => Self::OperatorKeyword,
            KeywordToken::Role => Self::Role,
            KeywordToken::Grant => Self::Grant,
            KeywordToken::On => Self::On,
            KeywordToken::To => Self::To,
            KeywordToken::Policy => Self::Policy,
            KeywordToken::Using => Self::Using,
            KeywordToken::Execute => Self::Execute,
            KeywordToken::Call => Self::Call,
            KeywordToken::Begin => Self::Begin,
            KeywordToken::Commit => Self::Commit,
            KeywordToken::Rollback => Self::Rollback,
            KeywordToken::And => Self::And,
            KeywordToken::Or => Self::Or,
            KeywordToken::Not => Self::Not,
            KeywordToken::Case => Self::Case,
            KeywordToken::When => Self::When,
            KeywordToken::Then => Self::Then,
            KeywordToken::Else => Self::Else,
            KeywordToken::End => Self::End,
            KeywordToken::Is => Self::Is,
            KeywordToken::Between => Self::Between,
            KeywordToken::In => Self::In,
            KeywordToken::Like => Self::Like,
            KeywordToken::Null => Self::Null,
            KeywordToken::True => Self::True,
            KeywordToken::False => Self::False,
            KeywordToken::Unknown => Self::Unknown,
            KeywordToken::Encrypted => Self::Encrypted,
            KeywordToken::Generated => Self::Generated,
            KeywordToken::Always => Self::Always,
            KeywordToken::Stored => Self::Stored,
            KeywordToken::Explain => Self::Explain,
            KeywordToken::Analyze => Self::Analyze,
        }
    }
}

static KEYWORDS: phf::Map<&'static str, KeywordToken> = phf::phf_map! {
    "select" => KeywordToken::Select,
    "union" => KeywordToken::Union,
    "intersect" => KeywordToken::Intersect,
    "except" => KeywordToken::Except,
    "with" => KeywordToken::With,
    "recursive" => KeywordToken::Recursive,
    "distinct" => KeywordToken::Distinct,
    "all" => KeywordToken::All,
    "as" => KeywordToken::As,
    "insert" => KeywordToken::Insert,
    "into" => KeywordToken::Into,
    "values" => KeywordToken::Values,
    "update" => KeywordToken::Update,
    "delete" => KeywordToken::Delete,
    "set" => KeywordToken::Set,
    "create" => KeywordToken::Create,
    "index" => KeywordToken::Index,
    "unique" => KeywordToken::Unique,
    "alter" => KeywordToken::Alter,
    "drop" => KeywordToken::Drop,
    "add" => KeywordToken::Add,
    "column" => KeywordToken::Column,
    "if" => KeywordToken::If,
    "exists" => KeywordToken::Exists,
    "table" => KeywordToken::Table,
    "from" => KeywordToken::From,
    "join" => KeywordToken::Join,
    "lateral" => KeywordToken::Lateral,
    "where" => KeywordToken::Where,
    "group" => KeywordToken::Group,
    "grouping" => KeywordToken::Grouping,
    "sets" => KeywordToken::Sets,
    "rollup" => KeywordToken::Rollup,
    "cube" => KeywordToken::Cube,
    "over" => KeywordToken::Over,
    "having" => KeywordToken::Having,
    "order" => KeywordToken::Order,
    "by" => KeywordToken::By,
    "asc" => KeywordToken::Asc,
    "desc" => KeywordToken::Desc,
    "nulls" => KeywordToken::Nulls,
    "first" => KeywordToken::First,
    "last" => KeywordToken::Last,
    "limit" => KeywordToken::Limit,
    "offset" => KeywordToken::Offset,
    "fetch" => KeywordToken::Fetch,
    "next" => KeywordToken::Next,
    "row" => KeywordToken::Row,
    "rows" => KeywordToken::Rows,
    "only" => KeywordToken::Only,
    "function" => KeywordToken::Function,
    "procedure" => KeywordToken::Procedure,
    "returns" => KeywordToken::Returns,
    "operator" => KeywordToken::OperatorKeyword,
    "role" => KeywordToken::Role,
    "grant" => KeywordToken::Grant,
    "on" => KeywordToken::On,
    "to" => KeywordToken::To,
    "policy" => KeywordToken::Policy,
    "using" => KeywordToken::Using,
    "execute" => KeywordToken::Execute,
    "call" => KeywordToken::Call,
    "begin" => KeywordToken::Begin,
    "commit" => KeywordToken::Commit,
    "rollback" => KeywordToken::Rollback,
    "and" => KeywordToken::And,
    "or" => KeywordToken::Or,
    "not" => KeywordToken::Not,
    "case" => KeywordToken::Case,
    "when" => KeywordToken::When,
    "then" => KeywordToken::Then,
    "else" => KeywordToken::Else,
    "end" => KeywordToken::End,
    "is" => KeywordToken::Is,
    "between" => KeywordToken::Between,
    "in" => KeywordToken::In,
    "like" => KeywordToken::Like,
    "null" => KeywordToken::Null,
    "true" => KeywordToken::True,
    "false" => KeywordToken::False,
    "unknown" => KeywordToken::Unknown,
    "encrypted" => KeywordToken::Encrypted,
    "generated" => KeywordToken::Generated,
    "always" => KeywordToken::Always,
    "stored" => KeywordToken::Stored,
    "explain" => KeywordToken::Explain,
    "analyze" => KeywordToken::Analyze,
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
    Index,
    Unique,
    Alter,
    Drop,
    Add,
    Column,
    If,
    Exists,
    Table,
    From,
    Join,
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
    Generated,
    Always,
    Stored,
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
        let kind = KEYWORDS
            .get(normalized.as_str())
            .copied()
            .map(TokenKind::from)
            .unwrap_or(TokenKind::Identifier(normalized));
        Token::new(kind, start, self.position)
    }

    fn lex_integer(&mut self) -> Result<Token> {
        let start = self.position;
        while let Some(b'0'..=b'9') = self.peek_byte() {
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
        self.position
            .checked_add(1)
            .and_then(|position| self.input.as_bytes().get(position))
            .copied()
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
