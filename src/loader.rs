//! Filter file loading utilities.
//!
//! Provides functions to load and compile filters from files.
//!
//! ## Filter File Format
//!
//! Filter files support comments, configuration directives, and the filter expression.
//!
//! ```text
//! # Comments start with #
//!
//! # Delimiter directive (optional, defaults to ";;;")
//! @delimiter = ";;;"
//!
//! # Field mappings
//! @field MESSAGE_TYPE = 1
//! @field MESSAGE_SUB_TYPE = 2
//! @field REQUEST_HEADERS = 11
//!
//! # The filter expression (everything else)
//! MESSAGE_TYPE == "2" AND MESSAGE_SUB_TYPE == "11"
//! ```

use std::fs;
use std::path::Path;

use crate::compiler::{compile, CompileError};
use crate::parser::ParserConfig;
use crate::vm::CompiledFilter;

/// Error type for filter loading.
#[derive(Debug)]
pub enum LoadError {
    /// IO error reading the file.
    Io(std::io::Error),
    /// Compilation error.
    Compile(CompileError),
    /// Invalid directive in filter file.
    InvalidDirective(String),
    /// Invalid field index.
    InvalidFieldIndex(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io(e) => write!(f, "IO error: {}", e),
            LoadError::Compile(e) => write!(f, "Compile error: {}", e),
            LoadError::InvalidDirective(s) => write!(f, "Invalid directive: {}", s),
            LoadError::InvalidFieldIndex(s) => write!(f, "Invalid field index: {}", s),
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LoadError::Io(e) => Some(e),
            LoadError::Compile(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for LoadError {
    fn from(e: std::io::Error) -> Self {
        LoadError::Io(e)
    }
}

impl From<CompileError> for LoadError {
    fn from(e: CompileError) -> Self {
        LoadError::Compile(e)
    }
}

/// Load and compile a filter from a file.
///
/// The file can contain:
/// - Comments (lines starting with `#`)
/// - Delimiter directive: `@delimiter = ";;;"`
/// - Field mappings: `@field FIELD_NAME = index`
/// - The filter expression
///
/// If the file contains `@delimiter` or `@field` directives, they override
/// the provided config.
///
/// # Arguments
/// * `path` - Path to the filter file
/// * `config` - Base parser configuration (can be overridden by file directives)
///
/// # Returns
/// A compiled filter ready for evaluation.
///
/// # Example
/// ```no_run
/// use bytecode_filter::{load_filter_file, ParserConfig};
///
/// let config = ParserConfig::default();
/// let filter = load_filter_file("filters/my.filter", &config).unwrap();
/// ```
///
/// # Errors
/// Returns `LoadError` if the file cannot be read or the filter fails to compile.
pub fn load_filter_file(
    path: impl AsRef<Path>,
    config: &ParserConfig,
) -> Result<CompiledFilter, LoadError> {
    let content = fs::read_to_string(path)?;
    load_filter_string(&content, config)
}

/// Load and compile a filter from a string.
///
/// Supports the same format as `load_filter_file`.
///
/// # Arguments
/// * `content` - The filter source string
/// * `config` - Base parser configuration (can be overridden by directives)
///
/// # Returns
/// A compiled filter ready for evaluation.
///
/// # Errors
/// Returns `LoadError` if parsing or compilation fails.
pub fn load_filter_string(
    content: &str,
    config: &ParserConfig,
) -> Result<CompiledFilter, LoadError> {
    let mut local_config = config.clone();
    let mut expression_lines = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip empty lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Parse directives
        if trimmed.starts_with('@') {
            parse_directive(trimmed, &mut local_config)?;
        } else {
            // Regular expression line — strip inline comments before joining.
            // Without this, joining lines with " " collapses newlines and the
            // lexer's # end-of-line comment would eat the rest of the expression.
            let without_comment = strip_inline_comment(trimmed);
            if !without_comment.is_empty() {
                expression_lines.push(without_comment);
            }
        }
    }

    let expression = expression_lines.join(" ");
    Ok(compile(&expression, &local_config)?)
}

/// Strip an inline `#` comment from an expression line, respecting quoted strings.
/// Returns the expression portion (trimmed), or "" if nothing remains.
fn strip_inline_comment(line: &str) -> &str {
    let mut in_quote: Option<char> = None;
    let mut prev_backslash = false;
    for (i, ch) in line.char_indices() {
        if prev_backslash {
            prev_backslash = false;
            continue;
        }
        if ch == '\\' {
            prev_backslash = true;
            continue;
        }
        match in_quote {
            Some(q) if ch == q => in_quote = None,
            Some(_) => {}
            None if ch == '"' || ch == '\'' => in_quote = Some(ch),
            None if ch == '#' => return line[..i].trim_end(),
            _ => {}
        }
    }
    line
}

/// Parse a directive line and update the config.
fn parse_directive(line: &str, config: &mut ParserConfig) -> Result<(), LoadError> {
    let line = line.trim_start_matches('@').trim();

    if line.starts_with("delimiter") {
        // @delimiter = ";;;"
        let parts: Vec<&str> = line.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(LoadError::InvalidDirective(format!(
                "Invalid delimiter directive: {}",
                line
            )));
        }
        let value = parts[1].trim();
        // Remove quotes and handle escape sequences
        let delimiter = value
            .trim_matches('"')
            .trim_matches('\'')
            .replace("\\t", "\t")
            .replace("\\n", "\n")
            .replace("\\r", "\r");
        config.delimiter = delimiter.into_bytes();
    } else if line.starts_with("field") {
        // @field FIELD_NAME = index
        let rest = line.trim_start_matches("field").trim();
        let parts: Vec<&str> = rest.splitn(2, '=').collect();
        if parts.len() != 2 {
            return Err(LoadError::InvalidDirective(format!(
                "Invalid field directive: {}",
                line
            )));
        }
        let field_name = parts[0].trim().to_string();
        let index_str = parts[1].trim();
        let index: u8 = index_str.parse().map_err(|_| {
            LoadError::InvalidFieldIndex(format!(
                "Invalid field index '{}' for field '{}'",
                index_str, field_name
            ))
        })?;
        config.fields.insert(field_name, index);
    } else {
        return Err(LoadError::InvalidDirective(format!(
            "Unknown directive: @{}",
            line
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn test_config() -> ParserConfig {
        let mut config = ParserConfig::default();
        config.add_field("LEVEL", 0);
        config.add_field("CODE", 1);
        config.add_field("BODY", 2);
        config
    }

    #[test]
    fn test_load_filter_string_with_comments() {
        let content = r#"
            # This is a comment
            LEVEL == "error"
            # Another comment
            AND CODE == "500"
        "#;

        let config = test_config();
        let filter = load_filter_string(content, &config).unwrap();

        assert!(filter.evaluate(Bytes::from("error;;;500;;;body")));
        assert!(!filter.evaluate(Bytes::from("info;;;500;;;body")));
    }

    #[test]
    fn test_load_filter_string_empty_lines() {
        let content = r#"
            LEVEL == "error"

            OR

            LEVEL == "warn"
        "#;

        let config = test_config();
        let filter = load_filter_string(content, &config).unwrap();

        assert!(filter.evaluate(Bytes::from("error;;;500;;;body")));
        assert!(filter.evaluate(Bytes::from("warn;;;500;;;body")));
        assert!(!filter.evaluate(Bytes::from("info;;;500;;;body")));
    }

    #[test]
    fn test_load_filter_with_directives() {
        let content = r#"
            # Test filter with embedded config
            @delimiter = ";;;"
            @field STATUS = 0
            @field CODE = 1

            STATUS == "ok" AND CODE == "200"
        "#;

        let config = ParserConfig::default();
        let filter = load_filter_string(content, &config).unwrap();

        assert!(filter.evaluate(Bytes::from("ok;;;200;;;body")));
        assert!(!filter.evaluate(Bytes::from("err;;;200;;;body")));
    }

    #[test]
    fn test_load_filter_with_pipe_delimiter() {
        let content = r#"
            @delimiter = "|"
            @field TYPE = 0
            @field VALUE = 1

            TYPE == "A" AND VALUE == "100"
        "#;

        let config = ParserConfig::default();
        let filter = load_filter_string(content, &config).unwrap();

        assert!(filter.evaluate(Bytes::from("A|100")));
        assert!(!filter.evaluate(Bytes::from("B|100")));
        assert!(!filter.evaluate(Bytes::from("A|200")));
    }

    #[test]
    fn test_load_filter_override_config() {
        let content = r#"
            @field EXTRA = 5

            EXTRA == "test"
        "#;

        let config = test_config();
        let filter = load_filter_string(content, &config).unwrap();

        let payload = Bytes::from("0;;;1;;;2;;;3;;;4;;;test");
        assert!(filter.evaluate(payload));
    }

    #[test]
    fn test_invalid_directive() {
        let content = r#"
            @unknown_directive = "value"
            LEVEL == "error"
        "#;

        let config = test_config();
        let result = load_filter_string(content, &config);
        assert!(matches!(result, Err(LoadError::InvalidDirective(_))));
    }

    #[test]
    fn test_invalid_field_index() {
        let content = r#"
            @field BAD_FIELD = not_a_number
            LEVEL == "error"
        "#;

        let config = test_config();
        let result = load_filter_string(content, &config);
        assert!(matches!(result, Err(LoadError::InvalidFieldIndex(_))));
    }

    #[test]
    fn test_inline_comments_not_swallowed_after_join() {
        // Inline # comments on each line must not eat subsequent AND clauses
        // when the loader joins expression lines with " ".
        let content = r#"
            LEVEL == "error" # check level
            AND CODE == "500" # check code
        "#;

        let config = test_config();
        let filter = load_filter_string(content, &config).unwrap();

        // Both conditions must be enforced
        assert!(filter.evaluate(Bytes::from("error;;;500;;;body")));
        assert!(!filter.evaluate(Bytes::from("error;;;200;;;body")));  // would pass if AND was eaten
        assert!(!filter.evaluate(Bytes::from("info;;;500;;;body")));
    }

    #[test]
    fn test_inline_comment_respects_quoted_hash() {
        // A # inside quotes must not be treated as a comment
        let content = r#"
            @field TAG = 0
            TAG == "a#b"
        "#;

        let mut config = ParserConfig::default();
        config.add_field("TAG", 0);
        let filter = load_filter_string(content, &config).unwrap();

        assert!(filter.evaluate(Bytes::from("a#b")));
        assert!(!filter.evaluate(Bytes::from("a")));
    }
}
