//! Lexer/tokenizer for filter expressions.
//!
//! Converts a filter string into a stream of tokens.

use thiserror::Error;

/// Token types for filter expressions.
#[derive(Debug, Clone, PartialEq)]
#[allow(missing_docs)]
pub enum Token {
    // Identifiers and literals
    Ident(String),  // Field names like MESSAGE_TYPE, payload
    String(String), // Quoted strings: "value"
    Number(u64),    // Numbers: 123
    Regex(String),  // Regex patterns: r"pattern" or /pattern/

    // Keywords
    And,        // AND, &&
    Or,         // OR, ||
    Not,        // NOT, !
    In,         // in
    Contains,   // contains
    IContains,  // icontains
    StartsWith, // starts_with
    EndsWith,   // ends_with
    Matches,    // matches
    IsEmpty,    // is_empty, EMPTY
    NotEmpty,   // not_empty, NOT EMPTY
    Header,     // header (for header extraction)
    IEquals,    // iequals, ieq
    Rand,       // rand

    // Operators
    Eq,     // ==
    Ne,     // !=
    Dot,    // .
    LParen, // (
    RParen, // )
    LBrace, // {
    RBrace, // }
    Comma,  // ,

    // End of input
    Eof,
}

/// Lexer error types.
#[derive(Debug, Clone, Error, PartialEq)]
#[allow(missing_docs)]
pub enum LexError {
    #[error("Unexpected character '{0}' at position {1}")]
    UnexpectedChar(char, usize),

    #[error("Unterminated string starting at position {0}")]
    UnterminatedString(usize),

    #[error("Unterminated regex starting at position {0}")]
    UnterminatedRegex(usize),

    #[error("Invalid escape sequence at position {0}")]
    InvalidEscape(usize),

    #[error("Invalid number at position {0}")]
    InvalidNumber(usize),
}

/// Lexer for filter expressions.
pub struct Lexer<'a> {
    input: &'a str,
    chars: std::iter::Peekable<std::str::CharIndices<'a>>,
    position: usize,
}

impl<'a> Lexer<'a> {
    /// Create a new lexer for the given input.
    pub fn new(input: &'a str) -> Self {
        Self {
            input,
            chars: input.char_indices().peekable(),
            position: 0,
        }
    }

    /// Get the next token.
    ///
    /// # Errors
    /// Returns `LexError` if an unexpected character is encountered.
    pub fn next_token(&mut self) -> Result<Token, LexError> {
        self.skip_whitespace();

        let Some(&(pos, ch)) = self.chars.peek() else {
            return Ok(Token::Eof);
        };

        self.position = pos;

        match ch {
            // Single-character tokens
            '(' => {
                self.chars.next();
                Ok(Token::LParen)
            }
            ')' => {
                self.chars.next();
                Ok(Token::RParen)
            }
            '{' => {
                self.chars.next();
                Ok(Token::LBrace)
            }
            '}' => {
                self.chars.next();
                Ok(Token::RBrace)
            }
            ',' => {
                self.chars.next();
                Ok(Token::Comma)
            }
            '.' => {
                self.chars.next();
                Ok(Token::Dot)
            }

            // Operators
            '=' => {
                self.chars.next();
                if self.chars.peek().map(|&(_, c)| c) == Some('=') {
                    self.chars.next();
                    Ok(Token::Eq)
                } else {
                    Ok(Token::Eq) // Single = also means ==
                }
            }
            '!' => {
                self.chars.next();
                if self.chars.peek().map(|&(_, c)| c) == Some('=') {
                    self.chars.next();
                    Ok(Token::Ne)
                } else {
                    Ok(Token::Not)
                }
            }
            '&' => {
                self.chars.next();
                if self.chars.peek().map(|&(_, c)| c) == Some('&') {
                    self.chars.next();
                }
                Ok(Token::And)
            }
            '|' => {
                self.chars.next();
                if self.chars.peek().map(|&(_, c)| c) == Some('|') {
                    self.chars.next();
                }
                Ok(Token::Or)
            }

            // Strings
            '"' | '\'' => self.read_string(ch),

            // Regex with r"..." or /.../ syntax
            'r' if self.peek_char(1) == Some('"') => self.read_regex_r(),
            '/' => self.read_regex_slash(),

            // Numbers
            '0'..='9' => self.read_number(),

            // Identifiers and keywords
            'a'..='z' | 'A'..='Z' | '_' => self.read_ident(),

            _ => Err(LexError::UnexpectedChar(ch, pos)),
        }
    }

    /// Tokenize the entire input.
    ///
    /// # Errors
    /// Returns `LexError` if tokenization fails.
    pub fn tokenize(&mut self) -> Result<Vec<Token>, LexError> {
        let mut tokens = Vec::new();
        loop {
            let token = self.next_token()?;
            if token == Token::Eof {
                break;
            }
            tokens.push(token);
        }
        Ok(tokens)
    }

    fn skip_whitespace(&mut self) {
        while let Some(&(_, ch)) = self.chars.peek() {
            if ch.is_whitespace() {
                self.chars.next();
            } else if ch == '#' {
                // Skip end-of-line comment: # ... until newline or EOF
                while let Some(&(_, c)) = self.chars.peek() {
                    if c == '\n' {
                        self.chars.next();
                        break;
                    }
                    self.chars.next();
                }
            } else {
                break;
            }
        }
    }

    fn peek_char(&self, offset: usize) -> Option<char> {
        self.input[self.position..].chars().nth(offset)
    }

    fn read_string(&mut self, quote: char) -> Result<Token, LexError> {
        let start = self.position;
        self.chars.next(); // consume opening quote

        let mut value = String::new();

        loop {
            match self.chars.next() {
                Some((_, ch)) if ch == quote => {
                    return Ok(Token::String(value));
                }
                Some((pos, '\\')) => {
                    // Escape sequence
                    match self.chars.next() {
                        Some((_, 'n')) => value.push('\n'),
                        Some((_, 'r')) => value.push('\r'),
                        Some((_, 't')) => value.push('\t'),
                        Some((_, '\\')) => value.push('\\'),
                        Some((_, c)) if c == quote => value.push(c),
                        Some((_, '"')) => value.push('"'),
                        Some((_, '\'')) => value.push('\''),
                        _ => return Err(LexError::InvalidEscape(pos)),
                    }
                }
                Some((_, ch)) => value.push(ch),
                None => return Err(LexError::UnterminatedString(start)),
            }
        }
    }

    fn read_regex_r(&mut self) -> Result<Token, LexError> {
        let start = self.position;
        self.chars.next(); // consume 'r'
        self.chars.next(); // consume '"'

        let mut pattern = String::new();

        loop {
            match self.chars.next() {
                Some((_, '"')) => {
                    return Ok(Token::Regex(pattern));
                }
                Some((_, '\\')) => {
                    // In raw regex, backslash is literal
                    pattern.push('\\');
                    if let Some((_, ch)) = self.chars.next() {
                        pattern.push(ch);
                    }
                }
                Some((_, ch)) => pattern.push(ch),
                None => return Err(LexError::UnterminatedRegex(start)),
            }
        }
    }

    fn read_regex_slash(&mut self) -> Result<Token, LexError> {
        let start = self.position;
        self.chars.next(); // consume '/'

        let mut pattern = String::new();

        loop {
            match self.chars.next() {
                Some((_, '/')) => {
                    // Check for flags (e.g., /pattern/i)
                    while let Some(&(_, ch)) = self.chars.peek() {
                        if ch.is_ascii_alphabetic() {
                            self.chars.next();
                            // For now, ignore flags - regex crate handles (?i) inline
                        } else {
                            break;
                        }
                    }
                    return Ok(Token::Regex(pattern));
                }
                Some((_, '\\')) => {
                    pattern.push('\\');
                    if let Some((_, ch)) = self.chars.next() {
                        pattern.push(ch);
                    }
                }
                Some((_, ch)) => pattern.push(ch),
                None => return Err(LexError::UnterminatedRegex(start)),
            }
        }
    }

    fn read_number(&mut self) -> Result<Token, LexError> {
        let start = self.position;
        let mut num_str = String::new();

        while let Some(&(_, ch)) = self.chars.peek() {
            if ch.is_ascii_digit() {
                num_str.push(ch);
                self.chars.next();
            } else {
                break;
            }
        }

        num_str
            .parse::<u64>()
            .map(Token::Number)
            .map_err(|_| LexError::InvalidNumber(start))
    }

    fn read_ident(&mut self) -> Result<Token, LexError> {
        let mut ident = String::new();

        while let Some(&(_, ch)) = self.chars.peek() {
            if ch.is_ascii_alphanumeric() || ch == '_' {
                ident.push(ch);
                self.chars.next();
            } else {
                break;
            }
        }

        // Check for keywords (case-insensitive)
        let token = match ident.to_ascii_lowercase().as_str() {
            "and" => Token::And,
            "or" => Token::Or,
            "not" => Token::Not,
            "in" => Token::In,
            "contains" => Token::Contains,
            "icontains" => Token::IContains,
            "starts_with" | "startswith" => Token::StartsWith,
            "ends_with" | "endswith" => Token::EndsWith,
            "matches" => Token::Matches,
            "is_empty" | "isempty" | "empty" => Token::IsEmpty,
            "not_empty" | "notempty" => Token::NotEmpty,
            "header" => Token::Header,
            "iequals" | "ieq" => Token::IEquals,
            "rand" | "random" => Token::Rand,
            "true" => return Ok(Token::Ident("true".into())),
            "false" => return Ok(Token::Ident("false".into())),
            _ => Token::Ident(ident),
        };

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokenize(input: &str) -> Result<Vec<Token>, LexError> {
        Lexer::new(input).tokenize()
    }

    #[test]
    fn test_simple_tokens() {
        assert_eq!(
            tokenize("(){},.").unwrap(),
            vec![
                Token::LParen,
                Token::RParen,
                Token::LBrace,
                Token::RBrace,
                Token::Comma,
                Token::Dot,
            ]
        );
    }

    #[test]
    fn test_operators() {
        assert_eq!(
            tokenize("== != && ||").unwrap(),
            vec![Token::Eq, Token::Ne, Token::And, Token::Or,]
        );
    }

    #[test]
    fn test_strings() {
        assert_eq!(
            tokenize(r#""hello" 'world'"#).unwrap(),
            vec![Token::String("hello".into()), Token::String("world".into()),]
        );
    }

    #[test]
    fn test_string_escapes() {
        assert_eq!(
            tokenize(r#""hello\nworld""#).unwrap(),
            vec![Token::String("hello\nworld".into()),]
        );
    }

    #[test]
    fn test_numbers() {
        assert_eq!(
            tokenize("123 456").unwrap(),
            vec![Token::Number(123), Token::Number(456),]
        );
    }

    #[test]
    fn test_keywords() {
        assert_eq!(
            tokenize("AND OR NOT contains matches").unwrap(),
            vec![
                Token::And,
                Token::Or,
                Token::Not,
                Token::Contains,
                Token::Matches,
            ]
        );
    }

    #[test]
    fn test_case_insensitive_keywords() {
        assert_eq!(
            tokenize("and AND And").unwrap(),
            vec![Token::And, Token::And, Token::And,]
        );
    }

    #[test]
    fn test_identifiers() {
        assert_eq!(
            tokenize("MESSAGE_TYPE field1").unwrap(),
            vec![
                Token::Ident("MESSAGE_TYPE".into()),
                Token::Ident("field1".into()),
            ]
        );
    }

    #[test]
    fn test_regex_r_syntax() {
        assert_eq!(
            tokenize(r#"r"hello.*world""#).unwrap(),
            vec![Token::Regex("hello.*world".into()),]
        );
    }

    #[test]
    fn test_regex_slash_syntax() {
        assert_eq!(
            tokenize(r#"/hello.*world/"#).unwrap(),
            vec![Token::Regex("hello.*world".into()),]
        );
    }

    #[test]
    fn test_complex_expression() {
        let input = r#"MESSAGE_TYPE == "2" AND payload contains "error""#;
        assert_eq!(
            tokenize(input).unwrap(),
            vec![
                Token::Ident("MESSAGE_TYPE".into()),
                Token::Eq,
                Token::String("2".into()),
                Token::And,
                Token::Ident("payload".into()),
                Token::Contains,
                Token::String("error".into()),
            ]
        );
    }

    #[test]
    fn test_rand() {
        assert_eq!(
            tokenize("rand(100)").unwrap(),
            vec![
                Token::Rand,
                Token::LParen,
                Token::Number(100),
                Token::RParen,
            ]
        );
    }

    #[test]
    fn test_in_set() {
        assert_eq!(
            tokenize(r#"field in {"a", "b", "c"}"#).unwrap(),
            vec![
                Token::Ident("field".into()),
                Token::In,
                Token::LBrace,
                Token::String("a".into()),
                Token::Comma,
                Token::String("b".into()),
                Token::Comma,
                Token::String("c".into()),
                Token::RBrace,
            ]
        );
    }

    #[test]
    fn test_header_syntax() {
        assert_eq!(
            tokenize(r#"field.header("X-Custom") iequals "value""#).unwrap(),
            vec![
                Token::Ident("field".into()),
                Token::Dot,
                Token::Header,
                Token::LParen,
                Token::String("X-Custom".into()),
                Token::RParen,
                Token::IEquals,
                Token::String("value".into()),
            ]
        );
    }

    #[test]
    fn test_end_of_line_comments() {
        // Comment at end of line
        let input = "MESSAGE_TYPE == \"2\" # check type\nAND MESSAGE_SUB_TYPE == \"11\" # CUSTOM PROBE";
        assert_eq!(
            tokenize(input).unwrap(),
            vec![
                Token::Ident("MESSAGE_TYPE".into()),
                Token::Eq,
                Token::String("2".into()),
                Token::And,
                Token::Ident("MESSAGE_SUB_TYPE".into()),
                Token::Eq,
                Token::String("11".into()),
            ]
        );

        // Comment at end of input (no trailing newline)
        assert_eq!(
            tokenize("true # done").unwrap(),
            vec![Token::Ident("true".into()),]
        );

        // Only a comment
        assert_eq!(tokenize("# nothing here").unwrap(), vec![]);
    }

    #[test]
    fn test_unterminated_string() {
        assert!(matches!(
            tokenize(r#""hello"#),
            Err(LexError::UnterminatedString(_))
        ));
    }

    #[test]
    fn test_unterminated_regex() {
        assert!(matches!(
            tokenize(r#"/hello"#),
            Err(LexError::UnterminatedRegex(_))
        ));
    }
}
