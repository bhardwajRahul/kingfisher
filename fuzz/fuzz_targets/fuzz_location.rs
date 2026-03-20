#![no_main]
use libfuzzer_sys::fuzz_target;
use kingfisher_core::location::{LocationMapping, OffsetSpan};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }

    // Use last 4 bytes to derive offsets, rest as the input text
    let text_len = data.len() - 4;
    let text = &data[..text_len];
    let offset_a = u16::from_le_bytes([data[text_len], data[text_len + 1]]) as usize;
    let offset_b = u16::from_le_bytes([data[text_len + 2], data[text_len + 3]]) as usize;

    let mapping = LocationMapping::new(text);

    // Exercise get_source_point with an arbitrary offset (may be beyond text length)
    let point = mapping.get_source_point(offset_a);
    assert!(point.line >= 1, "line numbers are 1-indexed");

    // Exercise get_source_span with a span that might be empty, inverted, or out of bounds
    let start = offset_a.min(offset_b);
    let end = offset_a.max(offset_b);
    let span = OffsetSpan { start, end };
    let _source_span = mapping.get_source_span(&span);
});
