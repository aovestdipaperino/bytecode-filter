//! Parser for filter expressions.
//!
//! Parses tokens into an AST that can be compiled to bytecode.

use std::collections::HashMap;

use thiserror::Error;

use crate::lexer::{LexError, Lexer, Token};

/// AST node for filter expressions.
#[derive(Debug, Clone, PartialEq)]
#[allow(missing_docs)]
pub enum Expr {
    /// Boolean literal: true or false
    Bool(bool),

    /// Random sampling: rand(N) returns true with probability 1/N
    Rand(u16),

    /// Payload-wide contains: payload contains "string"
    Contains(String),

    /// Payload-wide starts_with: payload starts_with "string"
    StartsWith(String),

    /// Payload-wide ends_with: payload ends_with "string"
    EndsWith(String),

    /// Payload-wide equals: payload == "string"
    Equals(String),

    /// Payload-wide regex match: payload matches "pattern"
    Matches(String),

    /// Part-specific contains: FIELD contains "string"
    PartContains { part: String, value: String },

    /// Part-specific case-insensitive contains
    PartIContains { part: String, value: String },

    /// Part-specific starts_with
    PartStartsWith { part: String, value: String },

    /// Part-specific ends_with
    PartEndsWith { part: String, value: String },

    /// Part-specific equals: FIELD == "string"
    PartEquals { part: String, value: String },

    /// Part-specific case-insensitive equals
    PartIEquals { part: String, value: String },

    /// Part-specific not equals: FIELD != "string"
    PartNotEquals { part: String, value: String },

    /// Part-specific regex match: FIELD matches "pattern"
    PartMatches { part: String, pattern: String },

    /// Part-specific set membership: FIELD in {"a", "b", "c"}
    PartInSet { part: String, values: Vec<String> },

    /// Part is empty: FIELD is_empty
    PartIsEmpty { part: String },

    /// Part is not empty: FIELD not_empty
    PartNotEmpty { part: String },

    /// Header extraction with equals: FIELD.header("name") == "value"
    HeaderEquals {
        part: String,
        header: String,
        value: String,
    },

    /// Header extraction with case-insensitive equals
    HeaderIEquals {
        part: String,
        header: String,
        value: String,
    },

    /// Header extraction with contains
    HeaderContains {
        part: String,
        header: String,
        value: String,
    },

    /// Header exists: FIELD.header("name") exists
    HeaderExists { part: String, header: String },

    /// Logical AND
    And(Box<Expr>, Box<Expr>),

    /// Logical OR
    Or(Box<Expr>, Box<Expr>),

    /// Logical NOT
    Not(Box<Expr>),
}

/// Parser error types.
#[derive(Debug, Clone, Error, PartialEq)]
#[allow(missing_docs)]
pub enum ParseError {
    #[error("Lexer error: {0}")]
    Lex(#[from] LexError),

    #[error("Unexpected token: expected {expected}, got {got:?}")]
    UnexpectedToken { expected: String, got: Token },

    #[error("Unexpected end of input, expected {0}")]
    UnexpectedEof(String),

    #[error("Unknown field '{0}'. Known fields: {1}")]
    UnknownField(String, String),

    #[error("Invalid rand() argument: must be > 0")]
    InvalidRandArg,

    #[error("Expected string literal")]
    ExpectedString,

    #[error("Expected number")]
    ExpectedNumber,

    #[error("Invalid regex pattern: {0}")]
    InvalidRegex(String),
}

/// Parser configuration with field mappings.
///
/// Define your record schema by mapping field names to positional indices
/// and specifying the delimiter used to split records into fields.
///
/// # Example
///
/// ```
/// use bytecode_filter::ParserConfig;
///
/// let mut config = ParserConfig::default();
/// config.set_delimiter(",");
/// config.add_field("STATUS", 0);
/// config.add_field("CODE", 1);
/// config.add_field("BODY", 2);
/// ```
#[derive(Debug, Clone)]
pub struct ParserConfig {
    /// Map of field names to part indices.
    pub fields: HashMap<String, u8>,

    /// The delimiter used to split records into fields.
    pub delimiter: Vec<u8>,
}

impl Default for ParserConfig {
    fn default() -> Self {
        Self {
            fields: HashMap::new(),
            delimiter: b";;;".to_vec(),
        }
    }
}

impl ParserConfig {
    /// Add a field mapping.
    pub fn add_field(&mut self, name: impl Into<String>, index: u8) -> &mut Self {
        self.fields.insert(name.into(), index);
        self
    }

    /// Set the delimiter.
    pub fn set_delimiter(&mut self, delimiter: impl Into<Vec<u8>>) -> &mut Self {
        self.delimiter = delimiter.into();
        self
    }
}

/// Parser for filter expressions.
pub struct Parser<'a> {
    tokens: Vec<Token>,
    pos: usize,
    #[allow(dead_code)]
    config: &'a ParserConfig,
}

impl<'a> Parser<'a> {
    /// Create a new parser from input string.
    ///
    /// # Errors
    /// Returns `ParseError` if tokenization fails.
    pub fn new(input: &str, config: &'a ParserConfig) -> Result<Self, ParseError> {
        let tokens = Lexer::new(input).tokenize()?;
        Ok(Self {
            tokens,
            pos: 0,
            config,
        })
    }

    /// Parse the expression.
    ///
    /// # Errors
    /// Returns `ParseError` if the expression syntax is invalid.
    pub fn parse(&mut self) -> Result<Expr, ParseError> {
        let expr = self.parse_or()?;

        if self.peek() != &Token::Eof {
            return Err(ParseError::UnexpectedToken {
                expected: "end of input".into(),
                got: self.peek().clone(),
            });
        }

        Ok(expr)
    }

    fn peek(&self) -> &Token {
        self.tokens.get(self.pos).unwrap_or(&Token::Eof)
    }

    fn advance(&mut self) -> &Token {
        let token = self.tokens.get(self.pos).unwrap_or(&Token::Eof);
        self.pos += 1;
        token
    }

    fn expect(&mut self, expected: &Token) -> Result<(), ParseError> {
        let got = self.advance().clone();
        if &got == expected {
            Ok(())
        } else {
            Err(ParseError::UnexpectedToken {
                expected: format!("{:?}", expected),
                got,
            })
        }
    }

    // Grammar:
    // expr     -> or_expr
    // or_expr  -> and_expr (OR and_expr)*
    // and_expr -> not_expr (AND not_expr)*
    // not_expr -> NOT not_expr | primary
    // primary  -> '(' expr ')' | rand | field_expr | true | false

    fn parse_or(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_and()?;

        while matches!(self.peek(), Token::Or) {
            self.advance();
            let right = self.parse_and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    fn parse_and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.parse_not()?;

        while matches!(self.peek(), Token::And) {
            self.advance();
            let right = self.parse_not()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }

        Ok(left)
    }

    fn parse_not(&mut self) -> Result<Expr, ParseError> {
        if matches!(self.peek(), Token::Not) {
            self.advance();
            let inner = self.parse_not()?;
            Ok(Expr::Not(Box::new(inner)))
        } else {
            self.parse_primary()
        }
    }

    fn parse_primary(&mut self) -> Result<Expr, ParseError> {
        match self.peek().clone() {
            Token::LParen => {
                self.advance();
                let expr = self.parse_or()?;
                self.expect(&Token::RParen)?;
                Ok(expr)
            }

            Token::Rand => self.parse_rand(),

            Token::Ident(name) => {
                self.advance();

                // Check for boolean literals
                if name == "true" {
                    return Ok(Expr::Bool(true));
                }
                if name == "false" {
                    return Ok(Expr::Bool(false));
                }

                // Check for "payload" keyword (full payload operations)
                if name.to_lowercase() == "payload" {
                    return self.parse_payload_op();
                }

                // Otherwise it's a field reference
                self.parse_field_op(name)
            }

            token => Err(ParseError::UnexpectedToken {
                expected: "expression".into(),
                got: token,
            }),
        }
    }

    fn parse_rand(&mut self) -> Result<Expr, ParseError> {
        self.advance(); // consume 'rand'
        self.expect(&Token::LParen)?;

        let n = match self.advance().clone() {
            Token::Number(n) => n,
            got => {
                return Err(ParseError::UnexpectedToken {
                    expected: "number".into(),
                    got,
                });
            }
        };

        if n == 0 || n > u16::MAX as u64 {
            return Err(ParseError::InvalidRandArg);
        }

        self.expect(&Token::RParen)?;
        Ok(Expr::Rand(n as u16))
    }

    fn parse_payload_op(&mut self) -> Result<Expr, ParseError> {
        match self.peek().clone() {
            Token::Contains => {
                self.advance();
                let value = self.expect_string()?;
                Ok(Expr::Contains(value))
            }
            Token::StartsWith => {
                self.advance();
                let value = self.expect_string()?;
                Ok(Expr::StartsWith(value))
            }
            Token::EndsWith => {
                self.advance();
                let value = self.expect_string()?;
                Ok(Expr::EndsWith(value))
            }
            Token::Matches => {
                self.advance();
                let pattern = self.expect_regex_or_string()?;
                Ok(Expr::Matches(pattern))
            }
            Token::Eq => {
                self.advance();
                let value = self.expect_string()?;
                Ok(Expr::Equals(value))
            }
            got => Err(ParseError::UnexpectedToken {
                expected: "contains, starts_with, ends_with, matches, or ==".into(),
                got,
            }),
        }
    }

    fn parse_field_op(&mut self, field_name: String) -> Result<Expr, ParseError> {
        // Check for header extraction: FIELD.header("name")
        if matches!(self.peek(), Token::Dot) {
            self.advance();
            if !matches!(self.peek(), Token::Header) {
                return Err(ParseError::UnexpectedToken {
                    expected: "header".into(),
                    got: self.peek().clone(),
                });
            }
            self.advance();
            self.expect(&Token::LParen)?;
            let header_name = self.expect_string()?;
            self.expect(&Token::RParen)?;

            return self.parse_header_op(field_name, header_name);
        }

        // Regular field operations
        match self.peek().clone() {
            Token::Contains => {
                self.advance();
                let value = self.expect_string()?;
                Ok(Expr::PartContains {
                    part: field_name,
                    value,
                })
            }
            Token::IContains => {
                self.advance();
                let value = self.expect_string()?;
                Ok(Expr::PartIContains {
                    part: field_name,
                    value,
                })
            }
            Token::StartsWith => {
                self.advance();
                let value = self.expect_string()?;
                Ok(Expr::PartStartsWith {
                    part: field_name,
                    value,
                })
            }
            Token::EndsWith => {
                self.advance();
                let value = self.expect_string()?;
                Ok(Expr::PartEndsWith {
                    part: field_name,
                    value,
                })
            }
            Token::Matches => {
                self.advance();
                let pattern = self.expect_regex_or_string()?;
                Ok(Expr::PartMatches {
                    part: field_name,
                    pattern,
                })
            }
            Token::Eq => {
                self.advance();
                let value = self.expect_string()?;
                Ok(Expr::PartEquals {
                    part: field_name,
                    value,
                })
            }
            Token::Ne => {
                self.advance();
                let value = self.expect_string()?;
                Ok(Expr::PartNotEquals {
                    part: field_name,
                    value,
                })
            }
            Token::IEquals => {
                self.advance();
                let value = self.expect_string()?;
                Ok(Expr::PartIEquals {
                    part: field_name,
                    value,
                })
            }
            Token::In => {
                self.advance();
                let values = self.parse_string_set()?;
                Ok(Expr::PartInSet {
                    part: field_name,
                    values,
                })
            }
            Token::IsEmpty => {
                self.advance();
                Ok(Expr::PartIsEmpty { part: field_name })
            }
            Token::NotEmpty => {
                self.advance();
                Ok(Expr::PartNotEmpty { part: field_name })
            }
            got => Err(ParseError::UnexpectedToken {
                expected:
                    "contains, starts_with, ends_with, matches, ==, !=, in, is_empty, or not_empty"
                        .into(),
                got,
            }),
        }
    }

    fn parse_header_op(&mut self, part: String, header: String) -> Result<Expr, ParseError> {
        match self.peek().clone() {
            Token::Eq => {
                self.advance();
                let value = self.expect_string()?;
                Ok(Expr::HeaderEquals {
                    part,
                    header,
                    value,
                })
            }
            Token::IEquals => {
                self.advance();
                let value = self.expect_string()?;
                Ok(Expr::HeaderIEquals {
                    part,
                    header,
                    value,
                })
            }
            Token::Contains => {
                self.advance();
                let value = self.expect_string()?;
                Ok(Expr::HeaderContains {
                    part,
                    header,
                    value,
                })
            }
            // "exists" as an identifier
            Token::Ident(ref s) if s.to_lowercase() == "exists" => {
                self.advance();
                Ok(Expr::HeaderExists { part, header })
            }
            got => Err(ParseError::UnexpectedToken {
                expected: "==, iequals, contains, or exists".into(),
                got,
            }),
        }
    }

    fn parse_string_set(&mut self) -> Result<Vec<String>, ParseError> {
        self.expect(&Token::LBrace)?;

        let mut values = Vec::new();

        // Handle empty set
        if matches!(self.peek(), Token::RBrace) {
            self.advance();
            return Ok(values);
        }

        // First value
        values.push(self.expect_string()?);

        // Additional values
        while matches!(self.peek(), Token::Comma) {
            self.advance();
            // Allow trailing comma
            if matches!(self.peek(), Token::RBrace) {
                break;
            }
            values.push(self.expect_string()?);
        }

        self.expect(&Token::RBrace)?;
        Ok(values)
    }

    fn expect_string(&mut self) -> Result<String, ParseError> {
        match self.advance().clone() {
            Token::String(s) => Ok(s),
            got => Err(ParseError::UnexpectedToken {
                expected: "string".into(),
                got,
            }),
        }
    }

    fn expect_regex_or_string(&mut self) -> Result<String, ParseError> {
        match self.advance().clone() {
            Token::String(s) | Token::Regex(s) => Ok(s),
            got => Err(ParseError::UnexpectedToken {
                expected: "string or regex".into(),
                got,
            }),
        }
    }
}

/// Parse a filter expression string.
///
/// # Errors
/// Returns `ParseError` if the expression is invalid.
pub fn parse(input: &str, config: &ParserConfig) -> Result<Expr, ParseError> {
    Parser::new(input, config)?.parse()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ParserConfig {
        let mut config = ParserConfig::default();
        config.add_field("LEVEL", 0);
        config.add_field("CODE", 1);
        config.add_field("METHOD", 2);
        config.add_field("PATH", 3);
        config.add_field("HEADERS", 4);
        config.add_field("BODY", 5);
        config
    }

    fn parse_expr(input: &str) -> Result<Expr, ParseError> {
        let config = test_config();
        parse(input, &config)
    }

    #[test]
    fn test_bool_literals() {
        assert_eq!(parse_expr("true").unwrap(), Expr::Bool(true));
        assert_eq!(parse_expr("false").unwrap(), Expr::Bool(false));
    }

    #[test]
    fn test_rand() {
        assert_eq!(parse_expr("rand(100)").unwrap(), Expr::Rand(100));
        assert_eq!(parse_expr("rand(1)").unwrap(), Expr::Rand(1));
    }

    #[test]
    fn test_payload_contains() {
        assert_eq!(
            parse_expr(r#"payload contains "error""#).unwrap(),
            Expr::Contains("error".into())
        );
    }

    #[test]
    fn test_payload_matches() {
        assert_eq!(
            parse_expr(r#"payload matches "error_[0-9]+""#).unwrap(),
            Expr::Matches("error_[0-9]+".into())
        );
    }

    #[test]
    fn test_field_equals() {
        assert_eq!(
            parse_expr(r#"LEVEL == "error""#).unwrap(),
            Expr::PartEquals {
                part: "LEVEL".into(),
                value: "error".into(),
            }
        );
    }

    #[test]
    fn test_field_in_set() {
        assert_eq!(
            parse_expr(r#"LEVEL in {"error", "warn", "fatal"}"#).unwrap(),
            Expr::PartInSet {
                part: "LEVEL".into(),
                values: vec!["error".into(), "warn".into(), "fatal".into()],
            }
        );
    }

    #[test]
    fn test_header_iequals() {
        assert_eq!(
            parse_expr(r#"HEADERS.header("x-custom") iequals "value""#).unwrap(),
            Expr::HeaderIEquals {
                part: "HEADERS".into(),
                header: "x-custom".into(),
                value: "value".into(),
            }
        );
    }

    #[test]
    fn test_and() {
        let expr = parse_expr(r#"LEVEL == "error" AND CODE == "500""#).unwrap();
        assert!(matches!(expr, Expr::And(_, _)));
    }

    #[test]
    fn test_or() {
        let expr = parse_expr(r#"LEVEL == "error" OR LEVEL == "warn""#).unwrap();
        assert!(matches!(expr, Expr::Or(_, _)));
    }

    #[test]
    fn test_not() {
        let expr = parse_expr(r#"NOT LEVEL == "debug""#).unwrap();
        assert!(matches!(expr, Expr::Not(_)));
    }

    #[test]
    fn test_parentheses() {
        let expr =
            parse_expr(r#"(LEVEL == "error" OR LEVEL == "warn") AND BODY not_empty"#).unwrap();
        match expr {
            Expr::And(left, _) => {
                assert!(matches!(*left, Expr::Or(_, _)));
            }
            _ => panic!("Expected And expression"),
        }
    }

    #[test]
    fn test_complex_filter() {
        let input = r#"
            CODE == "500"
            AND METHOD == "POST"
            AND HEADERS.header("Content-Type") iequals "application/json"
        "#;
        let expr = parse_expr(input).unwrap();

        match expr {
            Expr::And(left, right) => {
                assert!(matches!(*left, Expr::And(_, _)));
                assert!(matches!(*right, Expr::HeaderIEquals { .. }));
            }
            _ => panic!("Expected And expression"),
        }
    }

    #[test]
    fn test_field_is_empty() {
        assert_eq!(
            parse_expr("BODY is_empty").unwrap(),
            Expr::PartIsEmpty {
                part: "BODY".into()
            }
        );
    }

    #[test]
    fn test_field_not_empty() {
        assert_eq!(
            parse_expr("BODY not_empty").unwrap(),
            Expr::PartNotEmpty {
                part: "BODY".into()
            }
        );
    }

    #[test]
    fn test_combined_with_rand() {
        let expr = parse_expr(r#"LEVEL == "error" AND rand(100)"#).unwrap();
        match expr {
            Expr::And(left, right) => {
                assert!(matches!(*left, Expr::PartEquals { .. }));
                assert!(matches!(*right, Expr::Rand(100)));
            }
            _ => panic!("Expected And expression"),
        }
    }
}
