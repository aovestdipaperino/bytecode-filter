//! # bytecode-filter
//!
//! A fast bytecode-compiled filter engine for delimiter-separated records.
//!
//! Filters are expressed in a small DSL, compiled to bytecode at startup, and
//! evaluated with **zero allocations** in the hot path.
//!
//! ## Features
//!
//! - **Zero-copy evaluation**: Records are split into fields without copying
//! - **SIMD-accelerated string matching**: Uses `memchr` for fast substring search
//! - **Precompiled regex**: Regex patterns are compiled once at startup
//! - **Key-value extraction**: Extract and match key-value pairs from record fields
//! - **Random sampling**: Built-in `rand(N)` for probabilistic filtering
//!
//! ## Example
//!
//! ```rust
//! use bytecode_filter::{compile, ParserConfig};
//! use bytes::Bytes;
//!
//! // Define your record schema
//! let mut config = ParserConfig::default();
//! config.set_delimiter(",");
//! config.add_field("LEVEL", 0);
//! config.add_field("CODE", 1);
//! config.add_field("BODY", 2);
//!
//! // Compile a filter expression
//! let filter = compile(r#"LEVEL == "error" AND CODE == "500""#, &config).unwrap();
//!
//! // Evaluate against records
//! let record = Bytes::from("error,500,internal failure");
//! assert!(filter.evaluate(record));
//!
//! let record = Bytes::from("info,200,ok");
//! assert!(!filter.evaluate(record));
//! ```
//!
//! ## Filter Syntax
//!
//! ### Basic Operations
//!
//! ```text
//! # Boolean literals
//! true
//! false
//!
//! # Random sampling (returns true 1/N of the time)
//! rand(100)    # 1% sample
//! rand(2)      # 50% sample
//!
//! # Payload-wide operations (match against the entire record)
//! payload contains "error"
//! payload starts_with "ERROR:"
//! payload ends_with ".json"
//! payload == "exact match"
//! payload matches "error_[0-9]+"
//! ```
//!
//! ### Field Operations
//!
//! ```text
//! # Equality
//! STATUS == "active"
//! STATUS != "deleted"
//!
//! # Set membership
//! LEVEL in {"error", "warn", "fatal"}
//!
//! # String matching
//! PATH contains "/api/"
//! PATH starts_with "GET"
//! PATH matches "/api/v[0-9]+/.*"
//!
//! # Case-insensitive
//! METHOD icontains "post"
//! LEVEL iequals "Error"
//!
//! # Empty checks
//! NOTES is_empty
//! NOTES not_empty
//! ```
//!
//! ### Key-Value Extraction
//!
//! For fields that contain key-value data (e.g., HTTP headers, metadata),
//! you can extract individual values:
//!
//! ```text
//! HEADERS.header("Content-Type") == "application/json"
//! HEADERS.header("Authorization") contains "Bearer"
//! HEADERS.header("X-Request-Id") exists
//! ```
//!
//! ### Boolean Logic
//!
//! ```text
//! # AND, OR, NOT
//! LEVEL == "error" AND CODE == "500"
//! LEVEL == "warn" OR LEVEL == "error"
//! NOT LEVEL == "debug"
//!
//! # Parentheses for grouping
//! (LEVEL == "error" OR LEVEL == "warn") AND BODY not_empty
//! ```
//!
//! ## Custom Schemas
//!
//! Fields and delimiters are fully configurable via [`ParserConfig`]:
//!
//! ```rust
//! use bytecode_filter::ParserConfig;
//!
//! let mut config = ParserConfig::default();
//! config.set_delimiter("\t");       // tab-separated
//! config.add_field("HOST", 0);
//! config.add_field("LEVEL", 1);
//! config.add_field("MESSAGE", 2);
//! ```
//!
//! Alternatively, use filter files with inline directives:
//!
//! ```text
//! @delimiter = "\t"
//! @field HOST = 0
//! @field LEVEL = 1
//! @field MESSAGE = 2
//!
//! LEVEL == "error" AND MESSAGE contains "timeout"
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

mod compiler;
mod lexer;
mod loader;
mod opcode;
mod parser;
mod split;
mod vm;

pub use compiler::{compile, compile_expr, CompileError};
pub use lexer::{LexError, Lexer, Token};
pub use loader::{load_filter_file, load_filter_string, LoadError};
pub use opcode::Opcode;
pub use parser::{parse, Expr, ParseError, Parser, ParserConfig};
pub use split::{extract_header_value, PayloadParts, MAX_PARTS};
pub use vm::{reset_rand_counter, CompiledFilter};

#[cfg(test)]
mod integration_tests {
    use bytes::Bytes;

    use super::*;

    /// Helper: build a ParserConfig for a simple log-like schema.
    fn log_config() -> ParserConfig {
        let mut config = ParserConfig::default();
        config.add_field("LEVEL", 0);
        config.add_field("CODE", 1);
        config.add_field("METHOD", 2);
        config.add_field("PATH", 3);
        config.add_field("HEADERS", 4);
        config.add_field("BODY", 5);
        config
    }

    /// Build a test record with the given field values.
    fn make_record(fields: &[&str]) -> Bytes {
        Bytes::from(fields.join(";;;"))
    }

    /// Build a 6-field record with specific overrides.
    fn make_full_record(overrides: &[(usize, &str)]) -> Bytes {
        let mut fields = vec![""; 6];
        for (idx, value) in overrides {
            fields[*idx] = value;
        }
        make_record(&fields)
    }

    #[test]
    fn test_field_equality_and_headers() {
        let config = log_config();
        let filter = compile(
            r#"
            CODE == "500"
            AND METHOD == "POST"
            AND HEADERS.header("Content-Type") iequals "application/json"
            "#,
            &config,
        )
        .unwrap();

        // Matching case
        let record = make_full_record(&[
            (1, "500"),
            (2, "POST"),
            (4, "Content-Type: application/json\r\nHost: example.com\r\n"),
        ]);
        assert!(filter.evaluate(record), "Should match all three clauses");

        // Case-insensitive header value
        let record = make_full_record(&[
            (1, "500"),
            (2, "POST"),
            (4, "Content-Type: APPLICATION/JSON\r\n"),
        ]);
        assert!(filter.evaluate(record), "Should match case-insensitive");

        // Wrong CODE
        let record = make_full_record(&[
            (1, "200"),
            (2, "POST"),
            (4, "Content-Type: application/json\r\n"),
        ]);
        assert!(!filter.evaluate(record), "Should not match wrong code");

        // Wrong METHOD
        let record = make_full_record(&[
            (1, "500"),
            (2, "GET"),
            (4, "Content-Type: application/json\r\n"),
        ]);
        assert!(!filter.evaluate(record), "Should not match wrong method");

        // Missing header
        let record = make_full_record(&[(1, "500"), (2, "POST"), (4, "Host: example.com\r\n")]);
        assert!(!filter.evaluate(record), "Should not match missing header");
    }

    #[test]
    fn test_url_pattern_matching() {
        let config = log_config();
        let filter = compile(
            r#"
            LEVEL in {"error", "warn", "fatal"}
            AND PATH matches "(?i).*/(?:admin|internal)/.*"
            "#,
            &config,
        )
        .unwrap();

        for level in ["error", "warn", "fatal"] {
            let record = make_full_record(&[(0, level), (3, "GET /api/admin/users HTTP/1.1")]);
            assert!(
                filter.evaluate(record),
                "Should match level {} with admin URL",
                level
            );
        }

        let record = make_full_record(&[(0, "warn"), (3, "GET /internal/status HTTP/1.1")]);
        assert!(filter.evaluate(record), "Should match internal URL");

        // Non-matching: wrong level
        let record = make_full_record(&[(0, "debug"), (3, "GET /admin/users HTTP/1.1")]);
        assert!(!filter.evaluate(record), "Should not match debug level");

        // Non-matching: no sensitive URL
        let record = make_full_record(&[(0, "error"), (3, "GET /api/users HTTP/1.1")]);
        assert!(!filter.evaluate(record), "Should not match public URL");
    }

    #[test]
    fn test_combined_or() {
        let config = log_config();
        let filter = compile(
            r#"
            (
                CODE == "500"
                AND METHOD == "POST"
                AND HEADERS.header("Content-Type") iequals "application/json"
            )
            OR
            (
                LEVEL in {"error", "warn", "fatal"}
                AND PATH matches "(?i).*/admin/.*"
            )
            "#,
            &config,
        )
        .unwrap();

        // First branch match
        let record = make_full_record(&[
            (1, "500"),
            (2, "POST"),
            (4, "Content-Type: application/json\r\n"),
        ]);
        assert!(filter.evaluate(record), "Should match first branch");

        // Second branch match
        let record = make_full_record(&[(0, "error"), (3, "POST /api/admin/submit HTTP/1.1")]);
        assert!(filter.evaluate(record), "Should match second branch");

        // Neither branch
        let record = make_full_record(&[(0, "info"), (3, "GET /api/users HTTP/1.1")]);
        assert!(!filter.evaluate(record), "Should match neither branch");
    }

    #[test]
    fn test_rand_sampling() {
        vm::reset_rand_counter();

        let config = log_config();
        let filter = compile(r#"LEVEL == "error" AND rand(10)"#, &config).unwrap();

        let record = make_record(&["error", "500", "GET"]);
        let matches: usize = (0..100)
            .filter(|_| filter.evaluate(record.clone()))
            .count();

        assert!(
            matches == 10,
            "Expected exactly 10 matches with deterministic counter, got {}",
            matches
        );
    }

    #[test]
    fn test_empty_checks() {
        let config = log_config();

        let filter = compile("BODY is_empty", &config).unwrap();
        assert!(filter.evaluate(make_record(&["error", "500", "GET", "/", "", ""])));
        assert!(!filter.evaluate(make_record(&[
            "error",
            "500",
            "GET",
            "/",
            "",
            "some body"
        ])));

        let filter = compile("BODY not_empty", &config).unwrap();
        assert!(!filter.evaluate(make_record(&["error", "500", "GET", "/", "", ""])));
        assert!(filter.evaluate(make_record(&[
            "error",
            "500",
            "GET",
            "/",
            "",
            "some body"
        ])));
    }

    #[test]
    fn test_case_insensitive_contains() {
        let config = log_config();
        let filter = compile(r#"PATH icontains "ADMIN""#, &config).unwrap();

        assert!(filter.evaluate(make_full_record(&[(3, "GET /admin/users HTTP/1.1")])));
        assert!(filter.evaluate(make_full_record(&[(3, "GET /ADMIN/users HTTP/1.1")])));
        assert!(filter.evaluate(make_full_record(&[(3, "GET /Admin/users HTTP/1.1")])));
        assert!(!filter.evaluate(make_full_record(&[(3, "GET /api/users HTTP/1.1")])));
    }

    #[test]
    fn test_filter_stats() {
        let config = log_config();
        let filter = compile(
            r#"LEVEL in {"error", "warn"} AND payload matches "timeout""#,
            &config,
        )
        .unwrap();

        assert_eq!(filter.string_count(), 2); // "error" and "warn"
        assert_eq!(filter.regex_count(), 1); // "timeout"
        assert!(filter.bytecode_len() > 0);
        assert_eq!(filter.delimiter(), b";;;");
    }
}
