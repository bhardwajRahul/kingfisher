//! Shannon entropy calculation.
//!
//! Entropy is used to filter out low-entropy strings that are unlikely
//! to be real secrets.

/// Calculates the Shannon entropy of a byte slice.
///
/// Returns a value between 0.0 (completely uniform) and 8.0 (maximum entropy
/// for random bytes). Typical thresholds for secret detection are around 3.5-4.5.
///
/// # Examples
///
/// ```
/// use kingfisher_core::calculate_shannon_entropy;
///
/// // Low entropy (repeated character)
/// let entropy = calculate_shannon_entropy(b"aaaaaaaaaa");
/// assert!(entropy < 0.1);
///
/// // High entropy (random-looking)
/// let entropy = calculate_shannon_entropy(b"j2k#9K$mL*p&vN3");
/// assert!(entropy > 3.5);
/// ```
pub fn calculate_shannon_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }

    // Count occurrences of each byte value (0-255)
    let mut counts = [0u32; 256];
    for &byte in bytes {
        counts[byte as usize] += 1;
    }

    let total_bytes = bytes.len() as f32;

    // Sum entropy contribution for each byte that appears at least once
    counts.iter().filter(|&&count| count > 0).fold(0.0, |entropy, &count| {
        let probability = count as f32 / total_bytes;
        entropy - probability * probability.log2()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        let entropy = calculate_shannon_entropy(&[]);
        assert_eq!(entropy, 0.0);
        assert!(entropy.is_finite());
    }

    #[test]
    fn test_entropy_uniform() {
        // Single repeated byte should return 0.0
        let entropy = calculate_shannon_entropy(&[65, 65, 65, 65]);
        assert_eq!(entropy, 0.0);
        assert!(entropy.is_finite());
    }

    #[test]
    fn test_entropy_two_values() {
        // Even distribution of two bytes should be exactly 1.0
        let input = &[1, 2, 1, 2];
        let entropy = calculate_shannon_entropy(input);
        assert!((entropy - 1.0).abs() < 0.0001);
        assert!(entropy.is_finite());
    }

    #[test]
    fn test_entropy_password() {
        // Real password example should have mid-range entropy
        let password = "Password123!".as_bytes();
        let entropy = calculate_shannon_entropy(password);
        assert!(entropy > 2.5);
        assert!(entropy.is_finite());
    }

    #[test]
    fn test_entropy_random() {
        // Random-looking string should have high entropy
        let random = "j2k#9K$mL*p&vN3".as_bytes();
        let entropy = calculate_shannon_entropy(random);
        assert!(entropy > 3.5);
        assert!(entropy.is_finite());
    }
}
