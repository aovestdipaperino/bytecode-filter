//! Zero-copy payload splitting.
//!
//! Splits a payload by a delimiter into parts, returning slices into the original data.

use bytes::Bytes;
use memchr::memmem::Finder;

/// Maximum number of parts supported.
pub const MAX_PARTS: usize = 32;

/// Zero-copy payload splitter.
///
/// Splits a `Bytes` payload by a delimiter and provides access to individual parts
/// as slices into the original payload. No allocations occur during splitting.
///
/// Supports both eager splitting (via `split` / `split_with_finder`) and
/// demand-driven lazy splitting (via `new_lazy` + `ensure`).
#[derive(Debug)]
pub struct PayloadParts {
    /// The original payload (keeps Bytes alive for zero-copy access).
    payload: Bytes,

    /// Offsets for each part: (start, end) pairs.
    /// Uses u32 to save space - payloads > 4GB are not supported.
    offsets: [(u32, u32); MAX_PARTS],

    /// Number of parts found so far.
    count: usize,

    /// Current scan position for lazy splitting.
    scan_cursor: usize,

    /// Whether the entire payload has been scanned.
    finished: bool,
}

impl PayloadParts {
    /// Split a payload by the given delimiter.
    ///
    /// # Arguments
    /// * `payload` - The payload to split
    /// * `delimiter` - The delimiter bytes (e.g., `b";;;"`)
    ///
    /// # Returns
    /// A `PayloadParts` instance with zero-copy access to each part.
    ///
    /// # Performance
    /// - O(n) scan with SIMD-accelerated delimiter search
    /// - Zero heap allocations
    /// - Parts are slices into the original Bytes
    #[inline]
    pub fn split(payload: Bytes, delimiter: &[u8]) -> Self {
        let mut offsets = [(0u32, 0u32); MAX_PARTS];
        let mut count = 0;
        let mut start = 0usize;

        if delimiter.is_empty() {
            offsets[0] = (0, payload.len() as u32);
            return Self {
                payload,
                offsets,
                count: 1,
                scan_cursor: 0,
                finished: true,
            };
        }

        let finder = Finder::new(delimiter);
        let payload_len = payload.len();
        let data = payload.as_ref();

        while count < MAX_PARTS - 1 {
            if let Some(pos) = finder.find(&data[start..]) {
                offsets[count] = (start as u32, (start + pos) as u32);
                count += 1;
                start += pos + delimiter.len();
            } else {
                break;
            }
        }

        if start <= payload_len && count < MAX_PARTS {
            offsets[count] = (start as u32, payload_len as u32);
            count += 1;
        }

        Self {
            payload,
            offsets,
            count,
            scan_cursor: payload_len,
            finished: true,
        }
    }

    /// Split a payload using a pre-built `Finder`.
    ///
    /// This avoids rebuilding the SIMD searcher on every call.
    ///
    /// # Arguments
    /// * `payload` - The payload to split
    /// * `finder` - Pre-built delimiter finder
    /// * `delim_len` - Length of the delimiter in bytes
    #[inline]
    pub fn split_with_finder(payload: Bytes, finder: &Finder<'_>, delim_len: usize) -> Self {
        let mut offsets = [(0u32, 0u32); MAX_PARTS];
        let mut count = 0;
        let mut start = 0usize;

        if delim_len == 0 {
            offsets[0] = (0, payload.len() as u32);
            return Self {
                payload,
                offsets,
                count: 1,
                scan_cursor: 0,
                finished: true,
            };
        }

        let payload_len = payload.len();
        let data = payload.as_ref();

        while count < MAX_PARTS - 1 {
            if let Some(pos) = finder.find(&data[start..]) {
                offsets[count] = (start as u32, (start + pos) as u32);
                count += 1;
                start += pos + delim_len;
            } else {
                break;
            }
        }

        if start <= payload_len && count < MAX_PARTS {
            offsets[count] = (start as u32, payload_len as u32);
            count += 1;
        }

        Self {
            payload,
            offsets,
            count,
            scan_cursor: payload_len,
            finished: true,
        }
    }

    /// Create a lazy payload splitter that scans delimiters on demand.
    ///
    /// No scanning happens until `ensure()` is called.
    #[inline]
    pub fn new_lazy(payload: Bytes) -> Self {
        Self {
            payload,
            offsets: [(0u32, 0u32); MAX_PARTS],
            count: 0,
            scan_cursor: 0,
            finished: false,
        }
    }

    /// Ensure that part `index` is available by scanning delimiters incrementally.
    ///
    /// After this call, `self.get(index)` returns the correct slice if the part
    /// exists, or an empty slice if the payload has fewer parts.
    #[inline]
    pub fn ensure(&mut self, index: usize, finder: &Finder<'_>, delim_len: usize) {
        // Already have enough parts, or payload fully scanned
        if index < self.count || self.finished {
            return;
        }

        let data = self.payload.as_ref();

        while self.count <= index && !self.finished {
            if self.count >= MAX_PARTS - 1 {
                // Last slot — take remainder
                if self.scan_cursor <= data.len() {
                    self.offsets[self.count] =
                        (self.scan_cursor as u32, data.len() as u32);
                    self.count += 1;
                }
                self.finished = true;
                return;
            }

            if let Some(pos) = finder.find(&data[self.scan_cursor..]) {
                self.offsets[self.count] =
                    (self.scan_cursor as u32, (self.scan_cursor + pos) as u32);
                self.count += 1;
                self.scan_cursor += pos + delim_len;
            } else {
                // No more delimiters — remainder is last part
                if self.scan_cursor <= data.len() && self.count < MAX_PARTS {
                    self.offsets[self.count] =
                        (self.scan_cursor as u32, data.len() as u32);
                    self.count += 1;
                }
                self.finished = true;
                return;
            }
        }
    }

    /// Get the number of parts.
    #[inline]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if there are no parts.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get a part by index as a byte slice.
    ///
    /// Returns an empty slice if the index is out of bounds.
    #[inline]
    pub fn get(&self, index: usize) -> &[u8] {
        if index < self.count {
            let (start, end) = self.offsets[index];
            &self.payload[start as usize..end as usize]
        } else {
            &[]
        }
    }

    /// Get a part by index as a `Bytes` (zero-copy slice).
    ///
    /// Returns an empty `Bytes` if the index is out of bounds.
    #[inline]
    pub fn get_bytes(&self, index: usize) -> Bytes {
        if index < self.count {
            let (start, end) = self.offsets[index];
            self.payload.slice(start as usize..end as usize)
        } else {
            Bytes::new()
        }
    }

    /// Get the original payload.
    #[inline]
    pub fn payload(&self) -> &Bytes {
        &self.payload
    }

    /// Iterate over all parts as byte slices.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        (0..self.count).map(move |i| self.get(i))
    }
}

/// Extract an HTTP header value from a headers blob.
///
/// Headers format: `Header-Name: value\r\nOther-Header: value2\r\n`
///
/// # Arguments
/// * `headers` - The raw headers blob
/// * `header_name` - The header name to search for (case-insensitive)
///
/// # Returns
/// The header value if found, with leading/trailing whitespace trimmed.
#[inline]
pub fn extract_header_value<'a>(headers: &'a [u8], header_name: &[u8]) -> Option<&'a [u8]> {
    if headers.is_empty() || header_name.is_empty() {
        return None;
    }

    let mut line_start = 0;

    while line_start < headers.len() {
        // Find end of current line using SIMD-accelerated search
        let line_end = match memchr::memchr2(b'\r', b'\n', &headers[line_start..]) {
            Some(pos) => line_start + pos,
            None => headers.len(),
        };

        let line = &headers[line_start..line_end];

        // Check if line starts with header name followed by ':'
        if line.len() > header_name.len() {
            let potential_name = &line[..header_name.len()];
            if potential_name.eq_ignore_ascii_case(header_name) && line[header_name.len()] == b':' {
                // Found header, extract value
                let mut val_start = header_name.len() + 1;

                // Skip leading whitespace
                while val_start < line.len()
                    && (line[val_start] == b' ' || line[val_start] == b'\t')
                {
                    val_start += 1;
                }

                return Some(&line[val_start..]);
            }
        }

        // Move to next line - skip \r\n or \n
        line_start = line_end;
        if line_start < headers.len() && headers[line_start] == b'\r' {
            line_start += 1;
        }
        if line_start < headers.len() && headers[line_start] == b'\n' {
            line_start += 1;
        }

        // If we didn't move, we're stuck - break to avoid infinite loop
        if line_start == line_end {
            break;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_basic() {
        let payload = Bytes::from("a;;;b;;;c");
        let parts = PayloadParts::split(payload, b";;;");

        assert_eq!(parts.len(), 3);
        assert_eq!(parts.get(0), b"a");
        assert_eq!(parts.get(1), b"b");
        assert_eq!(parts.get(2), b"c");
    }

    #[test]
    fn test_split_no_delimiter() {
        let payload = Bytes::from("hello world");
        let parts = PayloadParts::split(payload, b";;;");

        assert_eq!(parts.len(), 1);
        assert_eq!(parts.get(0), b"hello world");
    }

    #[test]
    fn test_split_empty_parts() {
        let payload = Bytes::from("a;;;;;;b");
        let parts = PayloadParts::split(payload, b";;;");

        assert_eq!(parts.len(), 3);
        assert_eq!(parts.get(0), b"a");
        assert_eq!(parts.get(1), b"");
        assert_eq!(parts.get(2), b"b");
    }

    #[test]
    fn test_split_empty_payload() {
        let payload = Bytes::from("");
        let parts = PayloadParts::split(payload, b";;;");

        assert_eq!(parts.len(), 1);
        assert_eq!(parts.get(0), b"");
    }

    #[test]
    fn test_split_trailing_delimiter() {
        let payload = Bytes::from("a;;;b;;;");
        let parts = PayloadParts::split(payload, b";;;");

        assert_eq!(parts.len(), 3);
        assert_eq!(parts.get(0), b"a");
        assert_eq!(parts.get(1), b"b");
        assert_eq!(parts.get(2), b"");
    }

    #[test]
    fn test_split_single_char_delimiter() {
        let payload = Bytes::from("a|b|c|d");
        let parts = PayloadParts::split(payload, b"|");

        assert_eq!(parts.len(), 4);
        assert_eq!(parts.get(0), b"a");
        assert_eq!(parts.get(1), b"b");
        assert_eq!(parts.get(2), b"c");
        assert_eq!(parts.get(3), b"d");
    }

    #[test]
    fn test_get_out_of_bounds() {
        let payload = Bytes::from("a;;;b");
        let parts = PayloadParts::split(payload, b";;;");

        assert_eq!(parts.get(0), b"a");
        assert_eq!(parts.get(1), b"b");
        assert_eq!(parts.get(2), b""); // Out of bounds returns empty
        assert_eq!(parts.get(100), b"");
    }

    #[test]
    fn test_get_bytes_zero_copy() {
        let payload = Bytes::from("hello;;;world");
        let parts = PayloadParts::split(payload.clone(), b";;;");

        let part0 = parts.get_bytes(0);
        let part1 = parts.get_bytes(1);

        assert_eq!(&part0[..], b"hello");
        assert_eq!(&part1[..], b"world");

        // Verify it's truly zero-copy by checking pointer
        assert_eq!(part0.as_ptr(), payload.as_ptr());
    }

    #[test]
    fn test_extract_header_basic() {
        let headers = b"Content-Type: application/json\r\nX-Custom: value\r\n";

        assert_eq!(
            extract_header_value(headers, b"Content-Type"),
            Some(b"application/json".as_slice())
        );
        assert_eq!(
            extract_header_value(headers, b"X-Custom"),
            Some(b"value".as_slice())
        );
    }

    #[test]
    fn test_extract_header_case_insensitive() {
        let headers = b"Content-Type: application/json\r\n";

        assert_eq!(
            extract_header_value(headers, b"content-type"),
            Some(b"application/json".as_slice())
        );
        assert_eq!(
            extract_header_value(headers, b"CONTENT-TYPE"),
            Some(b"application/json".as_slice())
        );
    }

    #[test]
    fn test_extract_header_with_whitespace() {
        let headers = b"X-Custom:   value with spaces  \r\n";

        assert_eq!(
            extract_header_value(headers, b"X-Custom"),
            Some(b"value with spaces  ".as_slice())
        );
    }

    #[test]
    fn test_extract_header_not_found() {
        let headers = b"Content-Type: application/json\r\n";

        assert_eq!(extract_header_value(headers, b"X-Missing"), None);
    }

    #[test]
    fn test_extract_header_empty() {
        assert_eq!(extract_header_value(b"", b"Content-Type"), None);
        assert_eq!(extract_header_value(b"Content-Type: value", b""), None);
    }

    #[test]
    fn test_extract_header_no_crlf() {
        // Headers without \r\n (just \n)
        let headers = b"Content-Type: value\nX-Other: other\n";

        assert_eq!(
            extract_header_value(headers, b"Content-Type"),
            Some(b"value".as_slice())
        );
        assert_eq!(
            extract_header_value(headers, b"X-Other"),
            Some(b"other".as_slice())
        );
    }
}
