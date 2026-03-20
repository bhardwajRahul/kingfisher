#![no_main]
use libfuzzer_sys::fuzz_target;
use kingfisher_scanner::primitives::get_base64_strings;

fuzz_target!(|data: &[u8]| {
    let results = get_base64_strings(data);

    for decoded in &results {
        // Every returned span must be within the input bounds
        assert!(decoded.pos_start <= decoded.pos_end);
        assert!(decoded.pos_end <= data.len());
        // Decoded data must be non-empty and ASCII (per the function contract)
        assert!(!decoded.decoded.is_empty());
        assert!(decoded.decoded.is_ascii());
    }
});
