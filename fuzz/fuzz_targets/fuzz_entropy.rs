#![no_main]
use libfuzzer_sys::fuzz_target;
use kingfisher_core::calculate_shannon_entropy;

fuzz_target!(|data: &[u8]| {
    let entropy = calculate_shannon_entropy(data);
    // Invariants that must always hold:
    assert!(entropy.is_finite(), "entropy must be finite");
    assert!(entropy >= 0.0, "entropy must be non-negative");
    assert!(entropy <= 8.0, "entropy must be <= 8.0 for byte data");
});
