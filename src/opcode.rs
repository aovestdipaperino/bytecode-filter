//! Bytecode instruction set for filter evaluation.
//!
//! Each opcode is 1 byte, with operands following inline in the bytecode stream.

/// Bytecode opcodes for the filter VM.
///
/// Encoding:
/// - 1-byte opcode
/// - Variable operands depending on opcode type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opcode {
    // ============ Stack Operations ============
    /// Push `true` onto the stack.
    PushTrue = 0x01,

    /// Push `false` onto the stack.
    PushFalse = 0x02,

    // ============ Payload-wide String Operations ============
    // Operand: u16 string_index (little-endian)
    /// Check if payload contains the string at index.
    /// Bytecode: `[0x10, idx_lo, idx_hi]`
    Contains = 0x10,

    /// Check if payload starts with the string at index.
    /// Bytecode: `[0x11, idx_lo, idx_hi]`
    StartsWith = 0x11,

    /// Check if payload ends with the string at index.
    /// Bytecode: `[0x12, idx_lo, idx_hi]`
    EndsWith = 0x12,

    /// Check if payload equals the string at index.
    /// Bytecode: `[0x13, idx_lo, idx_hi]`
    Equals = 0x13,

    /// Check if payload matches the regex at index.
    /// Bytecode: `[0x20, idx_lo, idx_hi]`
    Matches = 0x20,

    // ============ Boolean Logic ============
    /// Pop 2 booleans, push (a AND b).
    /// Bytecode: `[0x30]`
    And = 0x30,

    /// Pop 2 booleans, push (a OR b).
    /// Bytecode: `[0x31]`
    Or = 0x31,

    /// Pop 1 boolean, push (NOT a).
    /// Bytecode: `[0x32]`
    Not = 0x32,

    // ============ Part-specific Operations ============
    // Operand: u8 part_index, u16 string_index
    /// Check if parts\[part_idx\] contains string at index.
    /// Bytecode: `[0x40, part_idx, str_idx_lo, str_idx_hi]`
    PartContains = 0x40,

    /// Check if parts\[part_idx\] starts with string at index.
    /// Bytecode: `[0x41, part_idx, str_idx_lo, str_idx_hi]`
    PartStartsWith = 0x41,

    /// Check if parts\[part_idx\] ends with string at index.
    /// Bytecode: `[0x42, part_idx, str_idx_lo, str_idx_hi]`
    PartEndsWith = 0x42,

    /// Check if parts\[part_idx\] equals string at index.
    /// Bytecode: `[0x43, part_idx, str_idx_lo, str_idx_hi]`
    PartEquals = 0x43,

    /// Check if parts\[part_idx\] matches regex at index.
    /// Bytecode: `[0x44, part_idx, regex_idx_lo, regex_idx_hi]`
    PartMatches = 0x44,

    /// Check if parts\[part_idx\] is empty.
    /// Bytecode: `[0x45, part_idx]`
    PartIsEmpty = 0x45,

    /// Check if parts\[part_idx\] is not empty.
    /// Bytecode: `[0x46, part_idx]`
    PartNotEmpty = 0x46,

    /// Check if parts\[part_idx\] equals any string in a set.
    /// Bytecode: `[0x47, part_idx, set_idx_lo, set_idx_hi]`
    PartInSet = 0x47,

    // ============ Case-insensitive Part Operations ============
    /// Case-insensitive equality check for parts\[part_idx\].
    /// Bytecode: `[0x48, part_idx, str_idx_lo, str_idx_hi]`
    PartIEquals = 0x48,

    /// Case-insensitive contains check for parts\[part_idx\].
    /// Bytecode: `[0x49, part_idx, str_idx_lo, str_idx_hi]`
    PartIContains = 0x49,

    // ============ Header Extraction Operations ============
    // Operand: u8 part_idx, u16 header_name_idx, u16 expected_value_idx
    /// Extract header from parts\[part_idx\], check exact equality.
    /// Bytecode: `[0x50, part_idx, hdr_idx_lo, hdr_idx_hi, val_idx_lo, val_idx_hi]`
    HeaderEquals = 0x50,

    /// Extract header from parts\[part_idx\], check case-insensitive equality.
    /// Bytecode: `[0x51, part_idx, hdr_idx_lo, hdr_idx_hi, val_idx_lo, val_idx_hi]`
    HeaderIEquals = 0x51,

    /// Extract header from parts\[part_idx\], check if value contains string.
    /// Bytecode: `[0x52, part_idx, hdr_idx_lo, hdr_idx_hi, val_idx_lo, val_idx_hi]`
    HeaderContains = 0x52,

    /// Check if header exists in parts\[part_idx\].
    /// Bytecode: `[0x53, part_idx, hdr_idx_lo, hdr_idx_hi]`
    HeaderExists = 0x53,

    // ============ Short-circuit Jumps ============
    /// If top of stack is false, jump by i16 offset (leave false on stack).
    /// If true, pop and continue to evaluate right operand.
    /// Bytecode: `[0x70, offset_lo, offset_hi]`
    JumpIfFalse = 0x70,

    /// If top of stack is true, jump by i16 offset (leave true on stack).
    /// If false, pop and continue to evaluate right operand.
    /// Bytecode: `[0x71, offset_lo, offset_hi]`
    JumpIfTrue = 0x71,

    // ============ Random Sampling ============
    /// Returns true with probability 1/N.
    /// Bytecode: `[0x60, n_lo, n_hi]`
    Rand = 0x60,

    // ============ Control ============
    /// Return the top of the stack as the filter result.
    /// Bytecode: `[0xFF]`
    Return = 0xFF,
}

impl Opcode {
    /// Decode an opcode from a byte.
    #[inline]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0x01 => Some(Opcode::PushTrue),
            0x02 => Some(Opcode::PushFalse),
            0x10 => Some(Opcode::Contains),
            0x11 => Some(Opcode::StartsWith),
            0x12 => Some(Opcode::EndsWith),
            0x13 => Some(Opcode::Equals),
            0x20 => Some(Opcode::Matches),
            0x30 => Some(Opcode::And),
            0x31 => Some(Opcode::Or),
            0x32 => Some(Opcode::Not),
            0x40 => Some(Opcode::PartContains),
            0x41 => Some(Opcode::PartStartsWith),
            0x42 => Some(Opcode::PartEndsWith),
            0x43 => Some(Opcode::PartEquals),
            0x44 => Some(Opcode::PartMatches),
            0x45 => Some(Opcode::PartIsEmpty),
            0x46 => Some(Opcode::PartNotEmpty),
            0x47 => Some(Opcode::PartInSet),
            0x48 => Some(Opcode::PartIEquals),
            0x49 => Some(Opcode::PartIContains),
            0x50 => Some(Opcode::HeaderEquals),
            0x51 => Some(Opcode::HeaderIEquals),
            0x52 => Some(Opcode::HeaderContains),
            0x53 => Some(Opcode::HeaderExists),
            0x60 => Some(Opcode::Rand),
            0x70 => Some(Opcode::JumpIfFalse),
            0x71 => Some(Opcode::JumpIfTrue),
            0xFF => Some(Opcode::Return),
            _ => None,
        }
    }

    /// Get the size of this instruction in bytes (opcode + operands).
    #[inline]
    pub fn instruction_size(&self) -> usize {
        match self {
            // No operands
            Opcode::PushTrue
            | Opcode::PushFalse
            | Opcode::And
            | Opcode::Or
            | Opcode::Not
            | Opcode::Return => 1,

            // u16 operand
            Opcode::Contains
            | Opcode::StartsWith
            | Opcode::EndsWith
            | Opcode::Equals
            | Opcode::Matches
            | Opcode::Rand
            | Opcode::JumpIfFalse
            | Opcode::JumpIfTrue => 3,

            // u8 part_idx only
            Opcode::PartIsEmpty | Opcode::PartNotEmpty => 2,

            // u8 part_idx + u16 string_idx
            Opcode::PartContains
            | Opcode::PartStartsWith
            | Opcode::PartEndsWith
            | Opcode::PartEquals
            | Opcode::PartMatches
            | Opcode::PartInSet
            | Opcode::PartIEquals
            | Opcode::PartIContains
            | Opcode::HeaderExists => 4,

            // u8 part_idx + u16 header_idx + u16 value_idx
            Opcode::HeaderEquals | Opcode::HeaderIEquals | Opcode::HeaderContains => 6,
        }
    }
}
