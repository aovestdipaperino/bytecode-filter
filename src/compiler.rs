//! Compiler for filter expressions.
//!
//! Compiles an AST into bytecode that can be executed by the VM.

use std::collections::HashMap;

use regex::bytes::Regex;
use thiserror::Error;

use crate::opcode::Opcode;
use crate::parser::{Expr, ParseError, ParserConfig};
use crate::vm::CompiledFilter;

/// Compilation error types.
#[derive(Debug, Clone, Error)]
#[allow(missing_docs)]
pub enum CompileError {
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),

    #[error("Unknown field '{0}'. Available fields: {1}")]
    UnknownField(String, String),

    #[error("Invalid regex pattern '{pattern}': {error}")]
    InvalidRegex { pattern: String, error: String },

    #[error("Too many strings (max 65535)")]
    TooManyStrings,

    #[error("Too many regexes (max 65535)")]
    TooManyRegexes,

    #[error("Too many string sets (max 65535)")]
    TooManySets,
}

/// Compiler state during bytecode generation.
struct Compiler<'a> {
    config: &'a ParserConfig,
    bytecode: Vec<u8>,
    strings: Vec<Vec<u8>>,
    string_map: HashMap<Vec<u8>, u16>,
    regexes: Vec<Regex>,
    regex_map: HashMap<String, u16>,
    string_sets: Vec<Vec<u16>>,
}

impl<'a> Compiler<'a> {
    fn new(config: &'a ParserConfig) -> Self {
        Self {
            config,
            bytecode: Vec::new(),
            strings: Vec::new(),
            string_map: HashMap::new(),
            regexes: Vec::new(),
            regex_map: HashMap::new(),
            string_sets: Vec::new(),
        }
    }

    /// Intern a string and return its index.
    fn intern_string(&mut self, s: &str) -> Result<u16, CompileError> {
        let bytes = s.as_bytes().to_vec();
        if let Some(&idx) = self.string_map.get(&bytes) {
            return Ok(idx);
        }

        let idx = self.strings.len();
        if idx > u16::MAX as usize {
            return Err(CompileError::TooManyStrings);
        }

        self.string_map.insert(bytes.clone(), idx as u16);
        self.strings.push(bytes);
        Ok(idx as u16)
    }

    /// Intern a regex and return its index.
    fn intern_regex(&mut self, pattern: &str) -> Result<u16, CompileError> {
        if let Some(&idx) = self.regex_map.get(pattern) {
            return Ok(idx);
        }

        let regex = Regex::new(pattern).map_err(|e| CompileError::InvalidRegex {
            pattern: pattern.to_string(),
            error: e.to_string(),
        })?;

        let idx = self.regexes.len();
        if idx > u16::MAX as usize {
            return Err(CompileError::TooManyRegexes);
        }

        self.regex_map.insert(pattern.to_string(), idx as u16);
        self.regexes.push(regex);
        Ok(idx as u16)
    }

    /// Add a string set and return its index.
    fn add_string_set(&mut self, values: &[String]) -> Result<u16, CompileError> {
        let indices: Vec<u16> = values
            .iter()
            .map(|v| self.intern_string(v))
            .collect::<Result<_, _>>()?;

        let idx = self.string_sets.len();
        if idx > u16::MAX as usize {
            return Err(CompileError::TooManySets);
        }

        self.string_sets.push(indices);
        Ok(idx as u16)
    }

    /// Look up a field name and return its part index.
    fn lookup_field(&self, name: &str) -> Result<u8, CompileError> {
        // Try case-insensitive lookup
        let upper = name.to_uppercase();
        self.config
            .fields
            .get(&upper)
            .or_else(|| self.config.fields.get(name))
            .copied()
            .ok_or_else(|| {
                let available: Vec<_> = self.config.fields.keys().cloned().collect();
                CompileError::UnknownField(name.to_string(), available.join(", "))
            })
    }

    /// Emit a single byte.
    fn emit(&mut self, byte: u8) {
        self.bytecode.push(byte);
    }

    /// Emit a u16 in little-endian format.
    fn emit_u16(&mut self, value: u16) {
        self.bytecode.extend_from_slice(&value.to_le_bytes());
    }

    /// Emit an i16 in little-endian format.
    fn emit_i16(&mut self, value: i16) {
        self.bytecode.extend_from_slice(&value.to_le_bytes());
    }

    /// Current bytecode offset (for backpatching).
    fn offset(&self) -> usize {
        self.bytecode.len()
    }

    /// Backpatch an i16 at the given bytecode position.
    fn patch_i16(&mut self, pos: usize, value: i16) {
        let bytes = value.to_le_bytes();
        self.bytecode[pos] = bytes[0];
        self.bytecode[pos + 1] = bytes[1];
    }

    /// Compile an expression.
    fn compile_expr(&mut self, expr: &Expr) -> Result<(), CompileError> {
        match expr {
            Expr::Bool(true) => {
                self.emit(Opcode::PushTrue as u8);
            }
            Expr::Bool(false) => {
                self.emit(Opcode::PushFalse as u8);
            }
            Expr::Rand(n) => {
                self.emit(Opcode::Rand as u8);
                self.emit_u16(*n);
            }

            // Payload-wide operations
            Expr::Contains(s) => {
                let idx = self.intern_string(s)?;
                self.emit(Opcode::Contains as u8);
                self.emit_u16(idx);
            }
            Expr::StartsWith(s) => {
                let idx = self.intern_string(s)?;
                self.emit(Opcode::StartsWith as u8);
                self.emit_u16(idx);
            }
            Expr::EndsWith(s) => {
                let idx = self.intern_string(s)?;
                self.emit(Opcode::EndsWith as u8);
                self.emit_u16(idx);
            }
            Expr::Equals(s) => {
                let idx = self.intern_string(s)?;
                self.emit(Opcode::Equals as u8);
                self.emit_u16(idx);
            }
            Expr::Matches(pattern) => {
                let idx = self.intern_regex(pattern)?;
                self.emit(Opcode::Matches as u8);
                self.emit_u16(idx);
            }

            // Part-specific operations
            Expr::PartContains { part, value } => {
                let part_idx = self.lookup_field(part)?;
                let str_idx = self.intern_string(value)?;
                self.emit(Opcode::PartContains as u8);
                self.emit(part_idx);
                self.emit_u16(str_idx);
            }
            Expr::PartIContains { part, value } => {
                let part_idx = self.lookup_field(part)?;
                let str_idx = self.intern_string(value)?;
                self.emit(Opcode::PartIContains as u8);
                self.emit(part_idx);
                self.emit_u16(str_idx);
            }
            Expr::PartStartsWith { part, value } => {
                let part_idx = self.lookup_field(part)?;
                let str_idx = self.intern_string(value)?;
                self.emit(Opcode::PartStartsWith as u8);
                self.emit(part_idx);
                self.emit_u16(str_idx);
            }
            Expr::PartEndsWith { part, value } => {
                let part_idx = self.lookup_field(part)?;
                let str_idx = self.intern_string(value)?;
                self.emit(Opcode::PartEndsWith as u8);
                self.emit(part_idx);
                self.emit_u16(str_idx);
            }
            Expr::PartEquals { part, value } => {
                let part_idx = self.lookup_field(part)?;
                let str_idx = self.intern_string(value)?;
                self.emit(Opcode::PartEquals as u8);
                self.emit(part_idx);
                self.emit_u16(str_idx);
            }
            Expr::PartIEquals { part, value } => {
                let part_idx = self.lookup_field(part)?;
                let str_idx = self.intern_string(value)?;
                self.emit(Opcode::PartIEquals as u8);
                self.emit(part_idx);
                self.emit_u16(str_idx);
            }
            Expr::PartNotEquals { part, value } => {
                // Compile as NOT (PartEquals)
                let part_idx = self.lookup_field(part)?;
                let str_idx = self.intern_string(value)?;
                self.emit(Opcode::PartEquals as u8);
                self.emit(part_idx);
                self.emit_u16(str_idx);
                self.emit(Opcode::Not as u8);
            }
            Expr::PartMatches { part, pattern } => {
                let part_idx = self.lookup_field(part)?;
                let regex_idx = self.intern_regex(pattern)?;
                self.emit(Opcode::PartMatches as u8);
                self.emit(part_idx);
                self.emit_u16(regex_idx);
            }
            Expr::PartInSet { part, values } => {
                let part_idx = self.lookup_field(part)?;
                let set_idx = self.add_string_set(values)?;
                self.emit(Opcode::PartInSet as u8);
                self.emit(part_idx);
                self.emit_u16(set_idx);
            }
            Expr::PartIsEmpty { part } => {
                let part_idx = self.lookup_field(part)?;
                self.emit(Opcode::PartIsEmpty as u8);
                self.emit(part_idx);
            }
            Expr::PartNotEmpty { part } => {
                let part_idx = self.lookup_field(part)?;
                self.emit(Opcode::PartNotEmpty as u8);
                self.emit(part_idx);
            }

            // Header operations
            Expr::HeaderEquals {
                part,
                header,
                value,
            } => {
                let part_idx = self.lookup_field(part)?;
                let hdr_idx = self.intern_string(header)?;
                let val_idx = self.intern_string(value)?;
                self.emit(Opcode::HeaderEquals as u8);
                self.emit(part_idx);
                self.emit_u16(hdr_idx);
                self.emit_u16(val_idx);
            }
            Expr::HeaderIEquals {
                part,
                header,
                value,
            } => {
                let part_idx = self.lookup_field(part)?;
                let hdr_idx = self.intern_string(header)?;
                let val_idx = self.intern_string(value)?;
                self.emit(Opcode::HeaderIEquals as u8);
                self.emit(part_idx);
                self.emit_u16(hdr_idx);
                self.emit_u16(val_idx);
            }
            Expr::HeaderContains {
                part,
                header,
                value,
            } => {
                let part_idx = self.lookup_field(part)?;
                let hdr_idx = self.intern_string(header)?;
                let val_idx = self.intern_string(value)?;
                self.emit(Opcode::HeaderContains as u8);
                self.emit(part_idx);
                self.emit_u16(hdr_idx);
                self.emit_u16(val_idx);
            }
            Expr::HeaderExists { part, header } => {
                let part_idx = self.lookup_field(part)?;
                let hdr_idx = self.intern_string(header)?;
                self.emit(Opcode::HeaderExists as u8);
                self.emit(part_idx);
                self.emit_u16(hdr_idx);
            }

            // Boolean operations — short-circuit with jumps
            Expr::And(left, right) => {
                // Emit left operand
                self.compile_expr(left)?;
                // JumpIfFalse: if left is false, skip right (leave false on stack)
                let opcode_pos = self.offset();
                self.emit(Opcode::JumpIfFalse as u8);
                let patch_pos = self.offset();
                self.emit_i16(0); // placeholder
                // Emit right operand (its result becomes the AND result)
                self.compile_expr(right)?;
                // Backpatch: offset is relative to opcode position (VM does pc += offset)
                let jump_target = self.offset();
                let offset = (jump_target as isize - opcode_pos as isize) as i16;
                self.patch_i16(patch_pos, offset);
            }
            Expr::Or(left, right) => {
                // Emit left operand
                self.compile_expr(left)?;
                // JumpIfTrue: if left is true, skip right (leave true on stack)
                let opcode_pos = self.offset();
                self.emit(Opcode::JumpIfTrue as u8);
                let patch_pos = self.offset();
                self.emit_i16(0); // placeholder
                // Emit right operand (its result becomes the OR result)
                self.compile_expr(right)?;
                // Backpatch: offset is relative to opcode position (VM does pc += offset)
                let jump_target = self.offset();
                let offset = (jump_target as isize - opcode_pos as isize) as i16;
                self.patch_i16(patch_pos, offset);
            }
            Expr::Not(inner) => {
                self.compile_expr(inner)?;
                self.emit(Opcode::Not as u8);
            }
        }

        Ok(())
    }

    /// Finish compilation and return the compiled filter.
    fn finish(mut self, source: String) -> CompiledFilter {
        self.emit(Opcode::Return as u8);

        CompiledFilter::new(
            self.bytecode,
            self.strings,
            self.regexes,
            self.string_sets,
            self.config.delimiter.clone(),
            source,
        )
    }
}

/// Compile a filter expression string into a CompiledFilter.
///
/// # Arguments
/// * `source` - The filter expression string
/// * `config` - Parser configuration with field mappings
///
/// # Returns
/// A `CompiledFilter` ready for evaluation.
///
/// # Example
/// ```
/// use bytecode_filter::{compile, ParserConfig};
/// use bytes::Bytes;
///
/// let mut config = ParserConfig::default();
/// config.add_field("STATUS", 0);
/// config.add_field("CODE", 1);
/// let filter = compile(r#"STATUS == "ok""#, &config).unwrap();
///
/// let record = Bytes::from("ok;;;200");
/// assert!(filter.evaluate(record));
/// ```
///
/// # Errors
/// Returns `CompileError` if parsing or compilation fails.
pub fn compile(source: &str, config: &ParserConfig) -> Result<CompiledFilter, CompileError> {
    let expr = crate::parser::parse(source, config)?;
    compile_expr(&expr, config, source.to_string())
}

/// Compile a pre-parsed AST into a CompiledFilter.
///
/// # Errors
/// Returns `CompileError` if the expression contains invalid operations.
pub fn compile_expr(
    expr: &Expr,
    config: &ParserConfig,
    source: String,
) -> Result<CompiledFilter, CompileError> {
    let mut compiler = Compiler::new(config);
    compiler.compile_expr(expr)?;
    Ok(compiler.finish(source))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

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

    fn compile_and_test(input: &str, payload: &str, expected: bool) {
        let config = test_config();
        let filter = compile(input, &config).expect("Failed to compile");
        let result = filter.evaluate(Bytes::from(payload.to_string()));
        assert_eq!(
            result, expected,
            "Filter '{}' on payload '{}' expected {} but got {}",
            input, payload, expected, result
        );
    }

    #[test]
    fn test_compile_true() {
        compile_and_test("true", "", true);
    }

    #[test]
    fn test_compile_false() {
        compile_and_test("false", "", false);
    }

    #[test]
    fn test_compile_payload_contains() {
        compile_and_test(r#"payload contains "error""#, "an error occurred", true);
        compile_and_test(r#"payload contains "error""#, "all good", false);
    }

    #[test]
    fn test_compile_field_equals() {
        compile_and_test(r#"LEVEL == "error""#, "error;;;500;;;GET", true);
        compile_and_test(r#"LEVEL == "error""#, "info;;;500;;;GET", false);
    }

    #[test]
    fn test_compile_field_in_set() {
        compile_and_test(r#"LEVEL in {"error", "warn", "fatal"}"#, "error;;;500;;;GET", true);
        compile_and_test(r#"LEVEL in {"error", "warn", "fatal"}"#, "warn;;;500;;;GET", true);
        compile_and_test(r#"LEVEL in {"error", "warn", "fatal"}"#, "info;;;500;;;GET", false);
    }

    #[test]
    fn test_compile_and() {
        compile_and_test(
            r#"LEVEL == "error" AND CODE == "500""#,
            "error;;;500;;;GET",
            true,
        );
        compile_and_test(
            r#"LEVEL == "error" AND CODE == "500""#,
            "error;;;200;;;GET",
            false,
        );
    }

    #[test]
    fn test_compile_or() {
        compile_and_test(
            r#"LEVEL == "error" OR LEVEL == "warn""#,
            "error;;;500;;;GET",
            true,
        );
        compile_and_test(
            r#"LEVEL == "error" OR LEVEL == "warn""#,
            "warn;;;500;;;GET",
            true,
        );
        compile_and_test(
            r#"LEVEL == "error" OR LEVEL == "warn""#,
            "info;;;500;;;GET",
            false,
        );
    }

    #[test]
    fn test_compile_not() {
        compile_and_test(r#"NOT LEVEL == "debug""#, "error;;;500;;;GET", true);
        compile_and_test(r#"NOT LEVEL == "debug""#, "debug;;;500;;;GET", false);
    }

    #[test]
    fn test_compile_header_iequals() {
        let mut parts = vec![""; 6];
        parts[0] = "error";
        parts[4] = "X-Custom: value\r\n";
        let payload = parts.join(";;;");

        let config = test_config();
        let filter = compile(
            r#"HEADERS.header("x-custom") iequals "value""#,
            &config,
        )
        .unwrap();

        assert!(filter.evaluate(Bytes::from(payload)));
    }

    #[test]
    fn test_compile_complex_filter() {
        let filter_str = r#"
            LEVEL == "error"
            AND CODE == "500"
            AND HEADERS.header("Content-Type") iequals "application/json"
        "#;

        let config = test_config();
        let filter = compile(filter_str, &config).unwrap();

        let mut parts = vec![""; 6];
        parts[0] = "error";
        parts[1] = "500";
        parts[4] = "Content-Type: application/json\r\n";
        let payload = parts.join(";;;");
        assert!(filter.evaluate(Bytes::from(payload)));

        parts[0] = "info";
        let payload = parts.join(";;;");
        assert!(!filter.evaluate(Bytes::from(payload)));
    }

    #[test]
    fn test_compile_rand() {
        crate::vm::reset_rand_counter();

        let config = test_config();
        let filter = compile("rand(2)", &config).unwrap();

        assert!(filter.evaluate(Bytes::new()));
        assert!(!filter.evaluate(Bytes::new()));
        assert!(filter.evaluate(Bytes::new()));
        assert!(!filter.evaluate(Bytes::new()));
    }

    #[test]
    fn test_compile_regex() {
        compile_and_test(r#"payload matches "error_[0-9]+""#, "found error_123", true);
        compile_and_test(r#"payload matches "error_[0-9]+""#, "no errors", false);
    }

    #[test]
    fn test_compile_unknown_field() {
        let config = test_config();
        let result = compile(r#"UNKNOWN_FIELD == "x""#, &config);
        assert!(matches!(result, Err(CompileError::UnknownField(_, _))));
    }

    #[test]
    fn test_compile_invalid_regex() {
        let config = test_config();
        let result = compile(r#"payload matches "[invalid""#, &config);
        assert!(matches!(result, Err(CompileError::InvalidRegex { .. })));
    }

    #[test]
    fn test_bytecode_size() {
        let config = test_config();

        let filter = compile(r#"LEVEL == "error""#, &config).unwrap();
        assert_eq!(filter.bytecode_len(), 5); // PartEquals(1 + 1 + 2) + Return(1)

        let filter = compile(
            r#"LEVEL == "error" AND CODE == "500""#,
            &config,
        )
        .unwrap();
        assert_eq!(filter.bytecode_len(), 12); // 2x PartEquals(4) + JumpIfFalse(3) + Return(1)
    }
}
