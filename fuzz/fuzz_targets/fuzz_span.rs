#![no_main]
use libfuzzer_sys::fuzz_target;
use kingfisher_core::OffsetSpan;
use kingfisher_scanner::primitives::insert_span;

fuzz_target!(|data: &[u8]| {
    // Interpret the input as a sequence of (start: u16, end: u16) span pairs
    if data.len() < 4 {
        return;
    }

    let mut spans: Vec<OffsetSpan> = Vec::new();
    let mut i = 0;
    while i + 3 < data.len() {
        let start = u16::from_le_bytes([data[i], data[i + 1]]) as usize;
        let end = u16::from_le_bytes([data[i + 2], data[i + 3]]) as usize;
        i += 4;

        let span = OffsetSpan { start, end };
        insert_span(&mut spans, span);

        // Invariant: the spans list must remain sorted by start offset
        for w in spans.windows(2) {
            assert!(w[0].start <= w[1].start, "spans must stay sorted");
        }
    }
});
