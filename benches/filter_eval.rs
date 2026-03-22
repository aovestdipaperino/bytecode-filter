use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use bytecode_filter::{compile, ParserConfig};

fn bench_config() -> ParserConfig {
    let mut config = ParserConfig::default();
    config.add_field("LEVEL", 0);
    config.add_field("CODE", 1);
    config.add_field("TIMESTAMP", 2);
    config.add_field("SOURCE", 3);
    config.add_field("METHOD", 4);
    config.add_field("PATH", 5);
    config.add_field("HEADERS", 6);
    config.add_field("BODY", 7);
    config.add_field("RESPONSE_STATUS", 8);
    config.add_field("RESPONSE_HEADERS", 9);
    config.add_field("RESPONSE_BODY", 10);
    config
}

/// Build a realistic 11-field record with `;;;` delimiters.
fn make_record(level: &str, code: &str, headers: &str) -> Bytes {
    let fields = [
        level,
        code,
        "1706886400000",
        "api-gateway",
        "POST",
        "/api/v2/resources",
        headers,
        r#"{"key":"value","count":42}"#,
        "HTTP/1.1 200 OK",
        "Content-Type: application/json\r\n",
        r#"{"status":"ok"}"#,
    ];
    Bytes::from(fields.join(";;;"))
}

fn filter_reject_first_field(c: &mut Criterion) {
    let config = bench_config();
    let filter = compile(
        r#"LEVEL == "error" AND CODE == "500" AND HEADERS.header("X-Priority") iequals "high""#,
        &config,
    )
    .unwrap();

    // LEVEL is "info" — rejected at first clause
    let record = make_record(
        "info",
        "500",
        "X-Priority: high\r\nContent-Type: text/html\r\n",
    );

    c.bench_function("filter_reject_first_field", |b| {
        b.iter(|| filter.evaluate(black_box(record.clone())))
    });
}

fn filter_reject_second_field(c: &mut Criterion) {
    let config = bench_config();
    let filter = compile(
        r#"LEVEL == "error" AND CODE == "500" AND HEADERS.header("X-Priority") iequals "high""#,
        &config,
    )
    .unwrap();

    // LEVEL matches but CODE is wrong
    let record = make_record(
        "error",
        "200",
        "X-Priority: high\r\nContent-Type: text/html\r\n",
    );

    c.bench_function("filter_reject_second_field", |b| {
        b.iter(|| filter.evaluate(black_box(record.clone())))
    });
}

fn filter_full_match(c: &mut Criterion) {
    let config = bench_config();
    let filter = compile(
        r#"LEVEL == "error" AND CODE == "500" AND HEADERS.header("X-Priority") iequals "high""#,
        &config,
    )
    .unwrap();

    // Full match — all three clauses pass
    let record = make_record(
        "error",
        "500",
        "X-Priority: high\r\nContent-Type: text/html\r\n",
    );

    c.bench_function("filter_full_match", |b| {
        b.iter(|| filter.evaluate(black_box(record.clone())))
    });
}

fn record_split_only(c: &mut Criterion) {
    use bytecode_filter::PayloadParts;

    let record = make_record(
        "error",
        "500",
        "X-Priority: high\r\nContent-Type: text/html\r\n",
    );

    c.bench_function("record_split_only", |b| {
        b.iter(|| PayloadParts::split(black_box(record.clone()), b";;;"))
    });
}

criterion_group!(
    benches,
    filter_reject_first_field,
    filter_reject_second_field,
    filter_full_match,
    record_split_only,
);
criterion_main!(benches);
