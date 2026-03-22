//! Bytecode virtual machine for filter evaluation.
//!
//! The VM executes compiled filter bytecode against a payload.

use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use memchr::memmem::Finder;
use regex::bytes::Regex;

use crate::split::{extract_header_value, PayloadParts};

/// Global counter for deterministic random sampling.
static RAND_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A compiled filter ready for evaluation.
///
/// This struct contains the bytecode and all pre-compiled resources
/// needed for fast evaluation. Create one at startup and reuse it
/// for all payload evaluations.
#[derive(Debug)]
pub struct CompiledFilter {
    /// Raw bytecode instructions.
    bytecode: Box<[u8]>,

    /// Pre-built string searchers for SIMD-accelerated matching.
    /// Each Finder contains the needle bytes.
    searchers: Box<[Finder<'static>]>,

    /// The raw string literals (for equality checks).
    strings: Box<[Box<[u8]>]>,

    /// Pre-compiled regex patterns.
    regexes: Box<[Regex]>,

    /// String sets for IN operations.
    /// Each set is a Vec of string indices.
    string_sets: Box<[Box<[u16]>]>,

    /// Delimiter for payload splitting.
    delimiter: Box<[u8]>,

    /// Pre-built SIMD-accelerated delimiter finder.
    delimiter_finder: Finder<'static>,

    /// Original filter source (for debugging).
    source: Box<str>,
}

impl CompiledFilter {
    /// Create a new compiled filter from components.
    ///
    /// This is typically called by the compiler, not directly.
    pub fn new(
        bytecode: Vec<u8>,
        strings: Vec<Vec<u8>>,
        regexes: Vec<Regex>,
        string_sets: Vec<Vec<u16>>,
        delimiter: Vec<u8>,
        source: String,
    ) -> Self {
        // Build SIMD searchers from strings
        let searchers: Vec<Finder<'static>> = strings
            .iter()
            .map(|s| {
                let bytes: &'static [u8] = Box::leak(s.clone().into_boxed_slice());
                Finder::new(bytes)
            })
            .collect();

        let strings: Vec<Box<[u8]>> = strings.into_iter().map(|s| s.into_boxed_slice()).collect();

        let string_sets: Vec<Box<[u16]>> = string_sets
            .into_iter()
            .map(|s| s.into_boxed_slice())
            .collect();

        let delimiter = delimiter.into_boxed_slice();
        let delim_bytes: &'static [u8] = Box::leak(delimiter.clone());
        let delimiter_finder = Finder::new(delim_bytes);

        Self {
            bytecode: bytecode.into_boxed_slice(),
            searchers: searchers.into_boxed_slice(),
            strings: strings.into_boxed_slice(),
            regexes: regexes.into_boxed_slice(),
            string_sets: string_sets.into_boxed_slice(),
            delimiter,
            delimiter_finder,
            source: source.into_boxed_str(),
        }
    }

    /// Evaluate the filter against a record.
    ///
    /// # Arguments
    /// * `payload` - The record payload to evaluate
    ///
    /// # Returns
    /// `true` if the filter matches, `false` otherwise.
    ///
    /// # Performance
    /// - Zero allocations during evaluation
    /// - SIMD-accelerated string matching
    /// - Fixed-size stack (no heap)
    ///
    /// # Panics
    ///
    /// In debug builds only, panics if the bytecode is malformed (invalid opcode
    /// or stack overflow). In release builds, returns `false` for invalid bytecode.
    #[inline]
    pub fn evaluate(&self, payload: Bytes) -> bool {
        // Demand-driven lazy splitting — delimiters are scanned only as needed
        let mut parts = PayloadParts::new_lazy(payload);
        let delim_len = self.delimiter.len();

        // Fixed-size evaluation stack
        let mut stack = [false; 32];
        let mut sp: usize = 0;
        let mut pc: usize = 0;

        let payload_bytes = parts.payload().as_ref() as *const [u8];
        // SAFETY: payload_bytes points to the Bytes buffer which lives as long as `parts`.
        // We only use it for read-only payload-wide operations. `parts` is not dropped
        // or reallocated during the loop, so the pointer remains valid.
        let payload_bytes: &[u8] = unsafe { &*payload_bytes };

        loop {
            debug_assert!(pc < self.bytecode.len(), "PC out of bounds");
            debug_assert!(sp < 32, "Stack overflow");

            match self.bytecode[pc] {
                // ============ Stack Operations ============
                0x01 => {
                    // PushTrue
                    stack[sp] = true;
                    sp += 1;
                    pc += 1;
                }
                0x02 => {
                    // PushFalse
                    stack[sp] = false;
                    sp += 1;
                    pc += 1;
                }

                // ============ Payload-wide Operations ============
                0x10 => {
                    // Contains
                    let idx = read_u16(&self.bytecode, pc + 1) as usize;
                    stack[sp] = self.searchers[idx].find(payload_bytes).is_some();
                    sp += 1;
                    pc += 3;
                }
                0x11 => {
                    // StartsWith
                    let idx = read_u16(&self.bytecode, pc + 1) as usize;
                    stack[sp] = payload_bytes.starts_with(&self.strings[idx]);
                    sp += 1;
                    pc += 3;
                }
                0x12 => {
                    // EndsWith
                    let idx = read_u16(&self.bytecode, pc + 1) as usize;
                    stack[sp] = payload_bytes.ends_with(&self.strings[idx]);
                    sp += 1;
                    pc += 3;
                }
                0x13 => {
                    // Equals
                    let idx = read_u16(&self.bytecode, pc + 1) as usize;
                    stack[sp] = payload_bytes == &self.strings[idx][..];
                    sp += 1;
                    pc += 3;
                }
                0x20 => {
                    // Matches (regex)
                    let idx = read_u16(&self.bytecode, pc + 1) as usize;
                    stack[sp] = self.regexes[idx].is_match(payload_bytes);
                    sp += 1;
                    pc += 3;
                }

                // ============ Boolean Logic ============
                0x30 => {
                    // And
                    debug_assert!(sp >= 2, "Stack underflow on AND");
                    sp -= 1;
                    stack[sp - 1] = stack[sp - 1] && stack[sp];
                    pc += 1;
                }
                0x31 => {
                    // Or
                    debug_assert!(sp >= 2, "Stack underflow on OR");
                    sp -= 1;
                    stack[sp - 1] = stack[sp - 1] || stack[sp];
                    pc += 1;
                }
                0x32 => {
                    // Not
                    debug_assert!(sp >= 1, "Stack underflow on NOT");
                    stack[sp - 1] = !stack[sp - 1];
                    pc += 1;
                }

                // ============ Part Operations ============
                0x40 => {
                    // PartContains
                    let part_idx = self.bytecode[pc + 1] as usize;
                    let str_idx = read_u16(&self.bytecode, pc + 2) as usize;
                    parts.ensure(part_idx, &self.delimiter_finder, delim_len);
                    let part = parts.get(part_idx);
                    stack[sp] = self.searchers[str_idx].find(part).is_some();
                    sp += 1;
                    pc += 4;
                }
                0x41 => {
                    // PartStartsWith
                    let part_idx = self.bytecode[pc + 1] as usize;
                    let str_idx = read_u16(&self.bytecode, pc + 2) as usize;
                    parts.ensure(part_idx, &self.delimiter_finder, delim_len);
                    let part = parts.get(part_idx);
                    stack[sp] = part.starts_with(&self.strings[str_idx]);
                    sp += 1;
                    pc += 4;
                }
                0x42 => {
                    // PartEndsWith
                    let part_idx = self.bytecode[pc + 1] as usize;
                    let str_idx = read_u16(&self.bytecode, pc + 2) as usize;
                    parts.ensure(part_idx, &self.delimiter_finder, delim_len);
                    let part = parts.get(part_idx);
                    stack[sp] = part.ends_with(&self.strings[str_idx]);
                    sp += 1;
                    pc += 4;
                }
                0x43 => {
                    // PartEquals
                    let part_idx = self.bytecode[pc + 1] as usize;
                    let str_idx = read_u16(&self.bytecode, pc + 2) as usize;
                    parts.ensure(part_idx, &self.delimiter_finder, delim_len);
                    let part = parts.get(part_idx);
                    stack[sp] = part == &self.strings[str_idx][..];
                    sp += 1;
                    pc += 4;
                }
                0x44 => {
                    // PartMatches
                    let part_idx = self.bytecode[pc + 1] as usize;
                    let regex_idx = read_u16(&self.bytecode, pc + 2) as usize;
                    parts.ensure(part_idx, &self.delimiter_finder, delim_len);
                    let part = parts.get(part_idx);
                    stack[sp] = self.regexes[regex_idx].is_match(part);
                    sp += 1;
                    pc += 4;
                }
                0x45 => {
                    // PartIsEmpty
                    let part_idx = self.bytecode[pc + 1] as usize;
                    parts.ensure(part_idx, &self.delimiter_finder, delim_len);
                    stack[sp] = parts.get(part_idx).is_empty();
                    sp += 1;
                    pc += 2;
                }
                0x46 => {
                    // PartNotEmpty
                    let part_idx = self.bytecode[pc + 1] as usize;
                    parts.ensure(part_idx, &self.delimiter_finder, delim_len);
                    stack[sp] = !parts.get(part_idx).is_empty();
                    sp += 1;
                    pc += 2;
                }
                0x47 => {
                    // PartInSet
                    let part_idx = self.bytecode[pc + 1] as usize;
                    let set_idx = read_u16(&self.bytecode, pc + 2) as usize;
                    parts.ensure(part_idx, &self.delimiter_finder, delim_len);
                    let part = parts.get(part_idx);
                    let set = &self.string_sets[set_idx];
                    stack[sp] = set
                        .iter()
                        .any(|&str_idx| part == &self.strings[str_idx as usize][..]);
                    sp += 1;
                    pc += 4;
                }
                0x48 => {
                    // PartIEquals (case-insensitive)
                    let part_idx = self.bytecode[pc + 1] as usize;
                    let str_idx = read_u16(&self.bytecode, pc + 2) as usize;
                    parts.ensure(part_idx, &self.delimiter_finder, delim_len);
                    let part = parts.get(part_idx);
                    stack[sp] = part.eq_ignore_ascii_case(&self.strings[str_idx]);
                    sp += 1;
                    pc += 4;
                }
                0x49 => {
                    // PartIContains (case-insensitive)
                    let part_idx = self.bytecode[pc + 1] as usize;
                    let str_idx = read_u16(&self.bytecode, pc + 2) as usize;
                    parts.ensure(part_idx, &self.delimiter_finder, delim_len);
                    let part = parts.get(part_idx);
                    let needle = &self.strings[str_idx];
                    stack[sp] = icontains(part, needle);
                    sp += 1;
                    pc += 4;
                }

                // ============ Header Operations ============
                0x50 => {
                    // HeaderEquals
                    let part_idx = self.bytecode[pc + 1] as usize;
                    let hdr_idx = read_u16(&self.bytecode, pc + 2) as usize;
                    let val_idx = read_u16(&self.bytecode, pc + 4) as usize;
                    parts.ensure(part_idx, &self.delimiter_finder, delim_len);
                    let headers = parts.get(part_idx);
                    let header_name = &self.strings[hdr_idx];
                    let expected = &self.strings[val_idx];
                    stack[sp] = extract_header_value(headers, header_name)
                        .map(|v| v == &expected[..])
                        .unwrap_or(false);
                    sp += 1;
                    pc += 6;
                }
                0x51 => {
                    // HeaderIEquals (case-insensitive)
                    let part_idx = self.bytecode[pc + 1] as usize;
                    let hdr_idx = read_u16(&self.bytecode, pc + 2) as usize;
                    let val_idx = read_u16(&self.bytecode, pc + 4) as usize;
                    parts.ensure(part_idx, &self.delimiter_finder, delim_len);
                    let headers = parts.get(part_idx);
                    let header_name = &self.strings[hdr_idx];
                    let expected = &self.strings[val_idx];
                    stack[sp] = extract_header_value(headers, header_name)
                        .map(|v| v.eq_ignore_ascii_case(expected))
                        .unwrap_or(false);
                    sp += 1;
                    pc += 6;
                }
                0x52 => {
                    // HeaderContains
                    let part_idx = self.bytecode[pc + 1] as usize;
                    let hdr_idx = read_u16(&self.bytecode, pc + 2) as usize;
                    let val_idx = read_u16(&self.bytecode, pc + 4) as usize;
                    parts.ensure(part_idx, &self.delimiter_finder, delim_len);
                    let headers = parts.get(part_idx);
                    let header_name = &self.strings[hdr_idx];
                    stack[sp] = extract_header_value(headers, header_name)
                        .map(|v| self.searchers[val_idx].find(v).is_some())
                        .unwrap_or(false);
                    sp += 1;
                    pc += 6;
                }
                0x53 => {
                    // HeaderExists
                    let part_idx = self.bytecode[pc + 1] as usize;
                    let hdr_idx = read_u16(&self.bytecode, pc + 2) as usize;
                    parts.ensure(part_idx, &self.delimiter_finder, delim_len);
                    let headers = parts.get(part_idx);
                    let header_name = &self.strings[hdr_idx];
                    stack[sp] = extract_header_value(headers, header_name).is_some();
                    sp += 1;
                    pc += 4;
                }

                // ============ Short-circuit Jumps ============
                0x70 => {
                    // JumpIfFalse — short-circuit AND
                    debug_assert!(sp >= 1, "Stack underflow on JumpIfFalse");
                    if !stack[sp - 1] {
                        // Left side is false → result is false, skip right operand
                        let offset = read_i16(&self.bytecode, pc + 1);
                        pc = (pc as isize + offset as isize) as usize;
                    } else {
                        // Left side is true → pop it, evaluate right operand
                        sp -= 1;
                        pc += 3;
                    }
                }
                0x71 => {
                    // JumpIfTrue — short-circuit OR
                    debug_assert!(sp >= 1, "Stack underflow on JumpIfTrue");
                    if stack[sp - 1] {
                        // Left side is true → result is true, skip right operand
                        let offset = read_i16(&self.bytecode, pc + 1);
                        pc = (pc as isize + offset as isize) as usize;
                    } else {
                        // Left side is false → pop it, evaluate right operand
                        sp -= 1;
                        pc += 3;
                    }
                }

                // ============ Random ============
                0x60 => {
                    // Rand
                    let n = read_u16(&self.bytecode, pc + 1);
                    stack[sp] = rand_1_in_n(n);
                    sp += 1;
                    pc += 3;
                }

                // ============ Control ============
                0xFF => {
                    // Return
                    debug_assert!(sp >= 1, "Stack underflow on RETURN");
                    return stack[sp - 1];
                }

                _ => {
                    // Unknown opcode - should never happen with valid bytecode
                    #[cfg(debug_assertions)]
                    panic!("Unknown opcode: 0x{:02X} at pc={}", self.bytecode[pc], pc);
                    #[cfg(not(debug_assertions))]
                    return false;
                }
            }
        }
    }

    /// Get the original filter source.
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Get the bytecode length.
    pub fn bytecode_len(&self) -> usize {
        self.bytecode.len()
    }

    /// Get the number of string literals.
    pub fn string_count(&self) -> usize {
        self.strings.len()
    }

    /// Get the number of regex patterns.
    pub fn regex_count(&self) -> usize {
        self.regexes.len()
    }

    /// Get the delimiter used for splitting.
    pub fn delimiter(&self) -> &[u8] {
        &self.delimiter
    }
}

/// Read a little-endian u16 from bytecode.
#[inline(always)]
fn read_u16(bytecode: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytecode[offset], bytecode[offset + 1]])
}

/// Read a little-endian i16 from bytecode.
#[inline(always)]
fn read_i16(bytecode: &[u8], offset: usize) -> i16 {
    i16::from_le_bytes([bytecode[offset], bytecode[offset + 1]])
}

/// Case-insensitive contains check.
#[inline]
fn icontains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }

    // Simple sliding window comparison
    for window in haystack.windows(needle.len()) {
        if window.eq_ignore_ascii_case(needle) {
            return true;
        }
    }
    false
}

/// Returns true with probability 1/N.
///
/// Uses a deterministic counter for reproducible sampling.
#[inline]
fn rand_1_in_n(n: u16) -> bool {
    if n <= 1 {
        return true;
    }
    let count = RAND_COUNTER.fetch_add(1, Ordering::Relaxed);
    count.is_multiple_of(n as u64)
}

/// Reset the random counter (for testing).
pub fn reset_rand_counter() {
    RAND_COUNTER.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_simple_filter(opcode: u8, str_idx: u16, needle: &str) -> CompiledFilter {
        let mut bytecode = vec![opcode];
        bytecode.extend_from_slice(&str_idx.to_le_bytes());
        bytecode.push(0xFF); // Return

        CompiledFilter::new(
            bytecode,
            vec![needle.as_bytes().to_vec()],
            vec![],
            vec![],
            b";;;".to_vec(),
            format!("test filter"),
        )
    }

    #[test]
    fn test_contains() {
        let filter = make_simple_filter(0x10, 0, "hello");
        assert!(filter.evaluate(Bytes::from("say hello world")));
        assert!(!filter.evaluate(Bytes::from("say goodbye")));
    }

    #[test]
    fn test_starts_with() {
        let filter = make_simple_filter(0x11, 0, "hello");
        assert!(filter.evaluate(Bytes::from("hello world")));
        assert!(!filter.evaluate(Bytes::from("say hello")));
    }

    #[test]
    fn test_ends_with() {
        let filter = make_simple_filter(0x12, 0, "world");
        assert!(filter.evaluate(Bytes::from("hello world")));
        assert!(!filter.evaluate(Bytes::from("world hello")));
    }

    #[test]
    fn test_equals() {
        let filter = make_simple_filter(0x13, 0, "hello");
        assert!(filter.evaluate(Bytes::from("hello")));
        assert!(!filter.evaluate(Bytes::from("hello world")));
    }

    #[test]
    fn test_push_true() {
        let filter = CompiledFilter::new(
            vec![0x01, 0xFF], // PushTrue, Return
            vec![],
            vec![],
            vec![],
            b";;;".to_vec(),
            "true".into(),
        );
        assert!(filter.evaluate(Bytes::from("anything")));
    }

    #[test]
    fn test_push_false() {
        let filter = CompiledFilter::new(
            vec![0x02, 0xFF], // PushFalse, Return
            vec![],
            vec![],
            vec![],
            b";;;".to_vec(),
            "false".into(),
        );
        assert!(!filter.evaluate(Bytes::from("anything")));
    }

    #[test]
    fn test_and() {
        // true AND true = true
        let filter = CompiledFilter::new(
            vec![0x01, 0x01, 0x30, 0xFF], // PushTrue, PushTrue, And, Return
            vec![],
            vec![],
            vec![],
            b";;;".to_vec(),
            "true AND true".into(),
        );
        assert!(filter.evaluate(Bytes::from("")));

        // true AND false = false
        let filter = CompiledFilter::new(
            vec![0x01, 0x02, 0x30, 0xFF], // PushTrue, PushFalse, And, Return
            vec![],
            vec![],
            vec![],
            b";;;".to_vec(),
            "true AND false".into(),
        );
        assert!(!filter.evaluate(Bytes::from("")));
    }

    #[test]
    fn test_or() {
        // false OR true = true
        let filter = CompiledFilter::new(
            vec![0x02, 0x01, 0x31, 0xFF], // PushFalse, PushTrue, Or, Return
            vec![],
            vec![],
            vec![],
            b";;;".to_vec(),
            "false OR true".into(),
        );
        assert!(filter.evaluate(Bytes::from("")));

        // false OR false = false
        let filter = CompiledFilter::new(
            vec![0x02, 0x02, 0x31, 0xFF], // PushFalse, PushFalse, Or, Return
            vec![],
            vec![],
            vec![],
            b";;;".to_vec(),
            "false OR false".into(),
        );
        assert!(!filter.evaluate(Bytes::from("")));
    }

    #[test]
    fn test_not() {
        // NOT true = false
        let filter = CompiledFilter::new(
            vec![0x01, 0x32, 0xFF], // PushTrue, Not, Return
            vec![],
            vec![],
            vec![],
            b";;;".to_vec(),
            "NOT true".into(),
        );
        assert!(!filter.evaluate(Bytes::from("")));

        // NOT false = true
        let filter = CompiledFilter::new(
            vec![0x02, 0x32, 0xFF], // PushFalse, Not, Return
            vec![],
            vec![],
            vec![],
            b";;;".to_vec(),
            "NOT false".into(),
        );
        assert!(filter.evaluate(Bytes::from("")));
    }

    #[test]
    fn test_part_equals() {
        // PartEquals(part=1, str=0) -> parts[1] == "2"
        let filter = CompiledFilter::new(
            vec![0x43, 0x01, 0x00, 0x00, 0xFF],
            vec![b"2".to_vec()],
            vec![],
            vec![],
            b";;;".to_vec(),
            "field[1] == \"2\"".into(),
        );

        assert!(filter.evaluate(Bytes::from("v1;;;2;;;subtype")));
        assert!(!filter.evaluate(Bytes::from("v1;;;1;;;subtype")));
    }

    #[test]
    fn test_part_in_set() {
        // PartInSet(part=1, set=0) -> parts[1] in {"1", "2", "3"}
        let filter = CompiledFilter::new(
            vec![0x47, 0x01, 0x00, 0x00, 0xFF],
            vec![b"1".to_vec(), b"2".to_vec(), b"3".to_vec()],
            vec![],
            vec![vec![0, 1, 2]], // Set 0 contains string indices 0, 1, 2
            b";;;".to_vec(),
            "field[1] in {\"1\", \"2\", \"3\"}".into(),
        );

        assert!(filter.evaluate(Bytes::from("v1;;;1;;;sub")));
        assert!(filter.evaluate(Bytes::from("v1;;;2;;;sub")));
        assert!(filter.evaluate(Bytes::from("v1;;;3;;;sub")));
        assert!(!filter.evaluate(Bytes::from("v1;;;4;;;sub")));
    }

    #[test]
    fn test_rand() {
        reset_rand_counter();

        // rand(2) should return true, false, true, false, ...
        let filter = CompiledFilter::new(
            vec![0x60, 0x02, 0x00, 0xFF], // Rand(2), Return
            vec![],
            vec![],
            vec![],
            b";;;".to_vec(),
            "rand(2)".into(),
        );

        let results: Vec<bool> = (0..10).map(|_| filter.evaluate(Bytes::from(""))).collect();
        assert_eq!(
            results,
            vec![true, false, true, false, true, false, true, false, true, false]
        );
    }

    #[test]
    fn test_rand_always_true() {
        reset_rand_counter();

        let filter = CompiledFilter::new(
            vec![0x60, 0x01, 0x00, 0xFF], // Rand(1), Return
            vec![],
            vec![],
            vec![],
            b";;;".to_vec(),
            "rand(1)".into(),
        );

        for _ in 0..10 {
            assert!(filter.evaluate(Bytes::from("")));
        }
    }

    #[test]
    fn test_regex_match() {
        let filter = CompiledFilter::new(
            vec![0x20, 0x00, 0x00, 0xFF], // Matches(regex=0), Return
            vec![],
            vec![Regex::new(r"error_[0-9]+").unwrap()],
            vec![],
            b";;;".to_vec(),
            "payload matches \"error_[0-9]+\"".into(),
        );

        assert!(filter.evaluate(Bytes::from("found error_123 in log")));
        assert!(filter.evaluate(Bytes::from("error_0")));
        assert!(!filter.evaluate(Bytes::from("error_abc")));
        assert!(!filter.evaluate(Bytes::from("no errors")));
    }

    #[test]
    fn test_header_iequals() {
        // HeaderIEquals(part=0, header="x-custom", value="expected")
        let filter = CompiledFilter::new(
            vec![0x51, 0x00, 0x00, 0x00, 0x01, 0x00, 0xFF],
            vec![b"x-custom".to_vec(), b"expected".to_vec()],
            vec![],
            vec![],
            b";;;".to_vec(),
            "headers.header(\"x-custom\") iequals \"expected\"".into(),
        );

        assert!(filter.evaluate(Bytes::from("X-Custom: expected\r\n")));
        assert!(filter.evaluate(Bytes::from("x-custom: EXPECTED\r\n")));
        assert!(filter.evaluate(Bytes::from("X-CUSTOM: Expected\r\n")));
        assert!(!filter.evaluate(Bytes::from("X-Custom: other\r\n")));
        assert!(!filter.evaluate(Bytes::from("X-Other: expected\r\n")));
    }

    #[test]
    fn test_complex_multi_clause_filter() {
        // field[1] == "error" AND field[2] == "500" AND header check
        // Bytecode:
        //   PartEquals(1, 0)    -> field[1] == "error"
        //   PartEquals(2, 1)    -> field[2] == "500"
        //   And
        //   HeaderIEquals(4, 2, 3) -> header check
        //   And
        //   Return
        let filter = CompiledFilter::new(
            vec![
                0x43, 0x01, 0x00, 0x00, // PartEquals(part=1, str=0)
                0x43, 0x02, 0x01, 0x00, // PartEquals(part=2, str=1)
                0x30, // And
                0x51, 0x04, 0x02, 0x00, 0x03, 0x00, // HeaderIEquals(part=4, hdr=2, val=3)
                0x30, // And
                0xFF, // Return
            ],
            vec![
                b"error".to_vec(),
                b"500".to_vec(),
                b"content-type".to_vec(),
                b"application/json".to_vec(),
            ],
            vec![],
            vec![],
            b";;;".to_vec(),
            "multi-clause filter".into(),
        );

        // Build a matching record: [ignored, "error", "500", ignored, headers, ...]
        let mut fields: Vec<&str> = vec![""; 6];
        fields[1] = "error";
        fields[2] = "500";
        fields[4] = "Content-Type: application/json\r\n";

        let payload = fields.join(";;;");
        assert!(filter.evaluate(Bytes::from(payload)));

        // Non-matching: wrong field[1]
        fields[1] = "info";
        let payload = fields.join(";;;");
        assert!(!filter.evaluate(Bytes::from(payload)));

        // Non-matching: wrong field[2]
        fields[1] = "error";
        fields[2] = "200";
        let payload = fields.join(";;;");
        assert!(!filter.evaluate(Bytes::from(payload)));

        // Non-matching: wrong header value
        fields[2] = "500";
        fields[4] = "Content-Type: text/html\r\n";
        let payload = fields.join(";;;");
        assert!(!filter.evaluate(Bytes::from(payload)));
    }
}
