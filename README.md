# bytecode-filter

A fast bytecode-compiled filter engine for delimiter-separated records.

Filters are expressed in a small DSL, compiled to bytecode at startup, and evaluated with **zero allocations** in the hot path.

## Features

- **Zero-copy evaluation** — records are split into fields without copying
- **SIMD-accelerated string matching** — uses `memchr` for fast substring search
- **Precompiled regex** — patterns compiled once at startup
- **Key-value extraction** — extract and match key-value pairs (e.g., HTTP headers) from record fields
- **Random sampling** — built-in `rand(N)` for probabilistic filtering
- **Short-circuit evaluation** — AND/OR skip unnecessary work via bytecode jumps

## Quick Start

```rust
use bytecode_filter::{compile, ParserConfig};
use bytes::Bytes;

// Define your record schema
let mut config = ParserConfig::default();
config.set_delimiter(",");
config.add_field("LEVEL", 0);
config.add_field("CODE", 1);
config.add_field("BODY", 2);

// Compile a filter expression
let filter = compile(r#"LEVEL == "error" AND CODE == "500""#, &config).unwrap();

// Evaluate against records
let record = Bytes::from("error,500,internal failure");
assert!(filter.evaluate(record));

let record = Bytes::from("info,200,ok");
assert!(!filter.evaluate(record));
```

## Filter Syntax

### Payload-wide operations

```text
payload contains "error"
payload starts_with "ERROR:"
payload ends_with ".json"
payload == "exact match"
payload matches "error_[0-9]+"
```

### Field operations

```text
STATUS == "active"
STATUS != "deleted"
LEVEL in {"error", "warn", "fatal"}
PATH contains "/api/"
PATH starts_with "GET"
PATH matches "/api/v[0-9]+/.*"
METHOD icontains "post"
LEVEL iequals "Error"
NOTES is_empty
NOTES not_empty
```

### Key-value extraction

```text
HEADERS.header("Content-Type") == "application/json"
HEADERS.header("Authorization") contains "Bearer"
HEADERS.header("X-Request-Id") exists
```

### Boolean logic

```text
LEVEL == "error" AND CODE == "500"
LEVEL == "warn" OR LEVEL == "error"
NOT LEVEL == "debug"
(LEVEL == "error" OR LEVEL == "warn") AND BODY not_empty
```

### Random sampling

```text
rand(100)   # matches 1% of records
rand(2)     # matches 50% of records
```

## Filter Files

Filters can be loaded from files with inline schema directives:

```text
# Log filter
@delimiter = "\t"
@field HOST = 0
@field LEVEL = 1
@field MESSAGE = 2

LEVEL == "error" AND MESSAGE contains "timeout"
```

```rust
use bytecode_filter::{load_filter_file, ParserConfig};

let config = ParserConfig::default();
let filter = load_filter_file("filters/errors.filter", &config).unwrap();
```

## Performance

The engine is designed for high-throughput filtering:

- Filters compile to a compact bytecode that runs on a fixed-size stack VM
- String searches use SIMD-accelerated `memchr::memmem::Finder`
- Records are split lazily — only the fields actually referenced by the filter are extracted
- No heap allocations during evaluation

## License

MIT
