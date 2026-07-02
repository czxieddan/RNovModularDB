use std::collections::{BTreeMap, BTreeSet};

use rnmdb_common::{ErrorKind, Result, RnovError};
use rnmdb_types::{LexemeWeight, TextLexeme, TextVector};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Token {
    term: String,
    position: u32,
}

impl Token {
    pub fn new(term: impl Into<String>, position: u32) -> Result<Self> {
        let term = term.into();
        if term.is_empty() {
            return Err(RnovError::new(ErrorKind::InvalidInput, "empty token term"));
        }
        if position == 0 {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "token position must be greater than zero",
            ));
        }
        Ok(Self { term, position })
    }

    pub fn term(&self) -> &str {
        &self.term
    }

    pub fn position(&self) -> u32 {
        self.position
    }
}

pub trait Tokenizer {
    fn tokenize(&self, input: &str) -> Result<Vec<Token>>;
}

pub trait TermStemmer {
    fn stem(&self, term: &str) -> Result<String>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IdentityStemmer;

impl TermStemmer for IdentityStemmer {
    fn stem(&self, term: &str) -> Result<String> {
        Ok(term.to_string())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimpleTokenizer<S = IdentityStemmer> {
    stop_words: BTreeSet<String>,
    stemmer: S,
}

impl Default for SimpleTokenizer<IdentityStemmer> {
    fn default() -> Self {
        Self {
            stop_words: BTreeSet::new(),
            stemmer: IdentityStemmer,
        }
    }
}

impl SimpleTokenizer {
    pub fn new() -> Self {
        Self::default()
    }
}

impl<S> SimpleTokenizer<S>
where
    S: TermStemmer,
{
    pub fn with_stop_words<I, W>(mut self, stop_words: I) -> Self
    where
        I: IntoIterator<Item = W>,
        W: AsRef<str>,
    {
        for word in stop_words {
            if let Ok(normalized) = normalize_term_with_stemmer(word.as_ref(), &self.stemmer)
                && !normalized.is_empty()
            {
                self.stop_words.insert(normalized);
            }
        }
        self
    }

    pub fn with_stemmer<T>(self, stemmer: T) -> SimpleTokenizer<T>
    where
        T: TermStemmer,
    {
        let stop_words = self
            .stop_words
            .into_iter()
            .filter_map(|word| match stemmer.stem(&word) {
                Ok(stemmed) if !stemmed.is_empty() => Some(stemmed),
                _ => None,
            })
            .collect();
        SimpleTokenizer {
            stop_words,
            stemmer,
        }
    }

    pub fn stop_words(&self) -> &BTreeSet<String> {
        &self.stop_words
    }

    pub fn tokenize(&self, input: &str) -> Result<Vec<Token>> {
        tokenize_with_stop_words_and_stemmer(input, &self.stop_words, &self.stemmer)
    }
}

impl<S> Tokenizer for SimpleTokenizer<S>
where
    S: TermStemmer,
{
    fn tokenize(&self, input: &str) -> Result<Vec<Token>> {
        self.tokenize(input)
    }
}

#[derive(Clone, Debug)]
pub struct TextVectorBuilder<T> {
    tokenizer: T,
    weight: LexemeWeight,
}

impl<T> TextVectorBuilder<T>
where
    T: Tokenizer,
{
    pub fn new(tokenizer: T) -> Self {
        Self {
            tokenizer,
            weight: LexemeWeight::D,
        }
    }

    pub fn with_weight(mut self, weight: LexemeWeight) -> Self {
        self.weight = weight;
        self
    }

    pub fn build(&self, input: &str) -> Result<TextVector> {
        let mut positions_by_term: BTreeMap<String, Vec<u32>> = BTreeMap::new();
        for token in self.tokenizer.tokenize(input)? {
            positions_by_term
                .entry(token.term)
                .or_default()
                .push(token.position);
        }

        let mut lexemes = Vec::with_capacity(positions_by_term.len());
        for (term, positions) in positions_by_term {
            lexemes.push(TextLexeme::new(term, positions, self.weight)?);
        }
        TextVector::from_lexemes(lexemes)
    }
}

fn flush_token(
    current: &mut String,
    raw_position: &mut u32,
    stop_words: &BTreeSet<String>,
    stemmer: &impl TermStemmer,
    tokens: &mut Vec<Token>,
) -> Result<()> {
    if current.is_empty() {
        return Ok(());
    }

    *raw_position = raw_position.checked_add(1).ok_or_else(|| {
        RnovError::new(
            ErrorKind::InvalidInput,
            "token position overflow while building text vector",
        )
    })?;
    let term = stemmer.stem(current)?;
    if !term.is_empty() && !stop_words.contains(&term) {
        tokens.push(Token::new(term, *raw_position)?);
    }
    current.clear();
    Ok(())
}

fn tokenize_with_stop_words_and_stemmer(
    input: &str,
    stop_words: &BTreeSet<String>,
    stemmer: &impl TermStemmer,
) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut raw_position = 0_u32;
    let mut current = String::new();

    for character in input.chars() {
        if character.is_alphanumeric() {
            current.extend(character.to_lowercase());
        } else {
            flush_token(
                &mut current,
                &mut raw_position,
                stop_words,
                stemmer,
                &mut tokens,
            )?;
        }
    }
    flush_token(
        &mut current,
        &mut raw_position,
        stop_words,
        stemmer,
        &mut tokens,
    )?;

    Ok(tokens)
}

fn normalize_term(term: &str) -> String {
    term.chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn normalize_term_with_stemmer(term: &str, stemmer: &impl TermStemmer) -> Result<String> {
    let normalized = normalize_term(term);
    if normalized.is_empty() {
        Ok(normalized)
    } else {
        stemmer.stem(&normalized)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextQuery {
    root: TextQueryExpr,
}

impl TextQuery {
    pub fn parse(input: &str) -> Result<Self> {
        Self::parse_with_stemmer(input, &IdentityStemmer)
    }

    pub fn parse_with_stemmer(input: &str, stemmer: &impl TermStemmer) -> Result<Self> {
        let tokens = QueryLexer::new(input).tokenize_with_stemmer(stemmer)?;
        if tokens.is_empty() {
            return Err(RnovError::new(ErrorKind::InvalidInput, "empty text query"));
        }

        let mut parser = QueryParser::new(tokens);
        let root = parser.parse_expr()?;
        if !parser.is_finished() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "unexpected text query token",
            ));
        }
        Ok(Self { root })
    }

    pub fn matches(&self, vector: &TextVector) -> bool {
        self.root.matches(vector)
    }

    pub fn rank(&self, vector: &TextVector) -> Option<TextRank> {
        if !self.matches(vector) {
            return None;
        }

        let mut positive_terms = BTreeSet::new();
        self.root.collect_positive_terms(&mut positive_terms);

        let mut score = 0_u32;
        let mut first_position: Option<u32> = None;
        let mut matched_terms = Vec::new();
        for term in positive_terms {
            let Some(lexeme) = vector.find(term) else {
                continue;
            };

            matched_terms.push(term.to_string());
            if let Some(position) = lexeme.positions().first().copied() {
                first_position =
                    Some(first_position.map_or(position, |existing| existing.min(position)));
                score = score.saturating_add(position_score(position));
            }
            score = score
                .saturating_add(weight_score(lexeme.weight()))
                .saturating_add((lexeme.positions().len() as u32).saturating_mul(2));
        }

        Some(TextRank {
            score,
            first_position,
            matched_terms,
        })
    }

    pub fn required_terms(&self) -> Vec<&str> {
        let mut terms = BTreeSet::new();
        self.root.collect_required_terms(&mut terms);
        terms.into_iter().collect()
    }

    pub fn optional_terms(&self) -> Vec<&str> {
        let mut terms = BTreeSet::new();
        self.root.collect_optional_terms(&mut terms);
        terms.into_iter().collect()
    }

    pub fn excluded_terms(&self) -> Vec<&str> {
        let mut terms = BTreeSet::new();
        self.root.collect_excluded_terms(&mut terms);
        terms.into_iter().collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextRank {
    score: u32,
    first_position: Option<u32>,
    matched_terms: Vec<String>,
}

impl TextRank {
    pub fn score(&self) -> u32 {
        self.score
    }

    pub fn first_position(&self) -> Option<u32> {
        self.first_position
    }

    pub fn matched_terms(&self) -> &[String] {
        &self.matched_terms
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TextQueryExpr {
    Term(String),
    And(Box<TextQueryExpr>, Box<TextQueryExpr>),
    Or(Box<TextQueryExpr>, Box<TextQueryExpr>),
    Not(Box<TextQueryExpr>),
}

impl TextQueryExpr {
    fn matches(&self, vector: &TextVector) -> bool {
        match self {
            Self::Term(term) => vector.find(term).is_some(),
            Self::And(left, right) => left.matches(vector) && right.matches(vector),
            Self::Or(left, right) => left.matches(vector) || right.matches(vector),
            Self::Not(expr) => !expr.matches(vector),
        }
    }

    fn collect_required_terms<'a>(&'a self, terms: &mut BTreeSet<&'a str>) {
        match self {
            Self::Term(term) => {
                terms.insert(term.as_str());
            }
            Self::And(left, right) => {
                left.collect_required_terms(terms);
                right.collect_required_terms(terms);
            }
            Self::Or(_, _) | Self::Not(_) => {}
        }
    }

    fn collect_optional_terms<'a>(&'a self, terms: &mut BTreeSet<&'a str>) {
        match self {
            Self::Term(_) | Self::Not(_) => {}
            Self::And(left, right) => {
                left.collect_optional_terms(terms);
                right.collect_optional_terms(terms);
            }
            Self::Or(left, right) => {
                left.collect_positive_terms(terms);
                right.collect_positive_terms(terms);
            }
        }
    }

    fn collect_excluded_terms<'a>(&'a self, terms: &mut BTreeSet<&'a str>) {
        match self {
            Self::Term(_) => {}
            Self::And(left, right) | Self::Or(left, right) => {
                left.collect_excluded_terms(terms);
                right.collect_excluded_terms(terms);
            }
            Self::Not(expr) => expr.collect_positive_terms(terms),
        }
    }

    fn collect_positive_terms<'a>(&'a self, terms: &mut BTreeSet<&'a str>) {
        match self {
            Self::Term(term) => {
                terms.insert(term.as_str());
            }
            Self::And(left, right) | Self::Or(left, right) => {
                left.collect_positive_terms(terms);
                right.collect_positive_terms(terms);
            }
            Self::Not(_) => {}
        }
    }
}

fn weight_score(weight: LexemeWeight) -> u32 {
    match weight {
        LexemeWeight::A => 40,
        LexemeWeight::B => 30,
        LexemeWeight::C => 20,
        LexemeWeight::D => 10,
    }
}

fn position_score(position: u32) -> u32 {
    16_u32.saturating_sub(position.min(16))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TextPhraseQuery {
    terms: Vec<String>,
    max_gap: u32,
}

impl TextPhraseQuery {
    pub fn exact<I, S>(terms: I) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::within(terms, 1)
    }

    pub fn exact_with_stemmer<I, S, T>(terms: I, stemmer: &T) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        T: TermStemmer,
    {
        Self::within_with_stemmer(terms, 1, stemmer)
    }

    pub fn within<I, S>(terms: I, max_gap: u32) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self::within_with_stemmer(terms, max_gap, &IdentityStemmer)
    }

    pub fn within_with_stemmer<I, S, T>(terms: I, max_gap: u32, stemmer: &T) -> Result<Self>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
        T: TermStemmer,
    {
        if max_gap == 0 {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "phrase position gap must be greater than zero",
            ));
        }

        let mut normalized_terms = Vec::new();
        for term in terms {
            let normalized = normalize_term_with_stemmer(term.as_ref(), stemmer)?;
            if normalized.is_empty() {
                return Err(RnovError::new(
                    ErrorKind::InvalidInput,
                    "phrase term cannot be empty",
                ));
            }
            normalized_terms.push(normalized);
        }
        if normalized_terms.is_empty() {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "phrase query must contain at least one term",
            ));
        }

        Ok(Self {
            terms: normalized_terms,
            max_gap,
        })
    }

    pub fn terms(&self) -> &[String] {
        &self.terms
    }

    pub fn max_gap(&self) -> u32 {
        self.max_gap
    }

    pub fn matches(&self, vector: &TextVector) -> bool {
        let Some(first_term) = self.terms.first() else {
            return false;
        };
        let Some(first_lexeme) = vector.find(first_term) else {
            return false;
        };

        first_lexeme
            .positions()
            .iter()
            .copied()
            .any(|position| self.matches_from(vector, 1, position))
    }

    fn matches_from(&self, vector: &TextVector, term_index: usize, previous_position: u32) -> bool {
        if term_index == self.terms.len() {
            return true;
        }

        let Some(lexeme) = vector.find(&self.terms[term_index]) else {
            return false;
        };
        lexeme.positions().iter().copied().any(|position| {
            position > previous_position
                && position - previous_position <= self.max_gap
                && self.matches_from(vector, term_index + 1, position)
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum QueryToken {
    Term(String),
    And,
    Or,
    Not,
    LeftParen,
    RightParen,
}

struct QueryLexer<'a> {
    input: &'a str,
}

impl<'a> QueryLexer<'a> {
    fn new(input: &'a str) -> Self {
        Self { input }
    }

    fn tokenize_with_stemmer(&self, stemmer: &impl TermStemmer) -> Result<Vec<QueryToken>> {
        let mut tokens = Vec::new();
        let mut chars = self.input.chars().peekable();

        while let Some(character) = chars.next() {
            match character {
                '&' => tokens.push(QueryToken::And),
                '|' => tokens.push(QueryToken::Or),
                '!' => tokens.push(QueryToken::Not),
                '(' => tokens.push(QueryToken::LeftParen),
                ')' => tokens.push(QueryToken::RightParen),
                whitespace if whitespace.is_whitespace() => {}
                term_start if term_start.is_alphanumeric() => {
                    let mut term = String::new();
                    term.extend(term_start.to_lowercase());
                    while let Some(next) = chars.peek().copied() {
                        if next.is_alphanumeric() {
                            chars.next();
                            term.extend(next.to_lowercase());
                        } else {
                            break;
                        }
                    }
                    let term = stemmer.stem(&term)?;
                    if !term.is_empty() {
                        tokens.push(QueryToken::Term(term));
                    }
                }
                invalid => {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        format!("invalid text query character {invalid:?}"),
                    ));
                }
            }
        }

        Ok(tokens)
    }
}

struct QueryParser {
    tokens: Vec<QueryToken>,
    position: usize,
}

impl QueryParser {
    fn new(tokens: Vec<QueryToken>) -> Self {
        Self {
            tokens,
            position: 0,
        }
    }

    fn parse_expr(&mut self) -> Result<TextQueryExpr> {
        self.parse_or()
    }

    fn parse_or(&mut self) -> Result<TextQueryExpr> {
        let mut expr = self.parse_and()?;
        while self.consume_if(QueryTokenKind::Or) {
            let right = self.parse_and()?;
            expr = TextQueryExpr::Or(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    fn parse_and(&mut self) -> Result<TextQueryExpr> {
        let mut expr = self.parse_unary()?;
        while self.consume_if(QueryTokenKind::And) {
            let right = self.parse_unary()?;
            expr = TextQueryExpr::And(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    fn parse_unary(&mut self) -> Result<TextQueryExpr> {
        if self.consume_if(QueryTokenKind::Not) {
            return Ok(TextQueryExpr::Not(Box::new(self.parse_unary()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<TextQueryExpr> {
        let Some(token) = self.advance() else {
            return Err(RnovError::new(
                ErrorKind::InvalidInput,
                "incomplete text query",
            ));
        };

        match token {
            QueryToken::Term(term) => Ok(TextQueryExpr::Term(term)),
            QueryToken::LeftParen => {
                let expr = self.parse_expr()?;
                if !self.consume_if(QueryTokenKind::RightParen) {
                    return Err(RnovError::new(
                        ErrorKind::InvalidInput,
                        "missing closing parenthesis in text query",
                    ));
                }
                Ok(expr)
            }
            QueryToken::RightParen => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "unexpected closing parenthesis in text query",
            )),
            QueryToken::And | QueryToken::Or | QueryToken::Not => Err(RnovError::new(
                ErrorKind::InvalidInput,
                "unexpected text query operator",
            )),
        }
    }

    fn is_finished(&self) -> bool {
        self.position == self.tokens.len()
    }

    fn advance(&mut self) -> Option<QueryToken> {
        let token = self.tokens.get(self.position).cloned()?;
        self.position += 1;
        Some(token)
    }

    fn consume_if(&mut self, kind: QueryTokenKind) -> bool {
        let Some(token) = self.tokens.get(self.position) else {
            return false;
        };
        if kind.matches(token) {
            self.position += 1;
            return true;
        }
        false
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueryTokenKind {
    And,
    Or,
    Not,
    RightParen,
}

impl QueryTokenKind {
    fn matches(self, token: &QueryToken) -> bool {
        matches!(
            (self, token),
            (Self::And, QueryToken::And)
                | (Self::Or, QueryToken::Or)
                | (Self::Not, QueryToken::Not)
                | (Self::RightParen, QueryToken::RightParen)
        )
    }
}
