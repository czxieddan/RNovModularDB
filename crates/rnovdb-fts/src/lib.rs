use std::collections::{BTreeMap, BTreeSet};

use rnovdb_common::{ErrorKind, Result, RnovError};
use rnovdb_types::{LexemeWeight, TextLexeme, TextVector};

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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SimpleTokenizer {
    stop_words: BTreeSet<String>,
}

impl SimpleTokenizer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_stop_words<I, S>(mut self, stop_words: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for word in stop_words {
            let normalized = normalize_term(word.as_ref());
            if !normalized.is_empty() {
                self.stop_words.insert(normalized);
            }
        }
        self
    }

    pub fn stop_words(&self) -> &BTreeSet<String> {
        &self.stop_words
    }

    pub fn tokenize(&self, input: &str) -> Result<Vec<Token>> {
        tokenize_with_stop_words(input, &self.stop_words)
    }
}

impl Tokenizer for SimpleTokenizer {
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
    if !stop_words.contains(current) {
        tokens.push(Token::new(current.clone(), *raw_position)?);
    }
    current.clear();
    Ok(())
}

fn tokenize_with_stop_words(input: &str, stop_words: &BTreeSet<String>) -> Result<Vec<Token>> {
    let mut tokens = Vec::new();
    let mut raw_position = 0_u32;
    let mut current = String::new();

    for character in input.chars() {
        if character.is_alphanumeric() {
            current.extend(character.to_lowercase());
        } else {
            flush_token(&mut current, &mut raw_position, stop_words, &mut tokens)?;
        }
    }
    flush_token(&mut current, &mut raw_position, stop_words, &mut tokens)?;

    Ok(tokens)
}

fn normalize_term(term: &str) -> String {
    term.chars()
        .filter(|character| character.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}
