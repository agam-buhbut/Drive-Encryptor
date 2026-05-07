//! 256-bit recovery key encoded as 16 groups of 6 decimal digits, BitLocker-style.
//!
//! Each group encodes a 16-bit value v as the 6-digit decimal integer `v * 11`.
//! Every encoded group is therefore divisible by 11 — this gives single-digit
//! transcription error detection within a group with probability ~10/11.
//!
//! Display: 4 rows of 4 groups, dashes within a row, newlines between rows.
//! Canonical machine form: 16 groups joined by '-' (no whitespace, no row breaks).
//! Liberal parser: strips whitespace, dashes, dots before validating.
//!
//! 16 groups × 16 bits = 256 bits — exact, no wasted entropy.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::errors::{Error, Result};

#[derive(Clone, ZeroizeOnDrop)]
pub struct RecoveryKey([u8; 32]);

impl RecoveryKey {
    pub const KEY_BYTES: usize = 32;
    pub const GROUPS: usize = 16;
    pub const DIGITS_PER_GROUP: usize = 6;
    pub const TOTAL_DIGITS: usize = Self::GROUPS * Self::DIGITS_PER_GROUP;

    pub fn generate() -> Result<Self> {
        let mut key = [0u8; Self::KEY_BYTES];
        getrandom::getrandom(&mut key).map_err(|e| Error::Rng(e.to_string()))?;
        Ok(Self(key))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Canonical machine form: 16 groups of 6 digits joined by '-'.
    pub fn encode(&self) -> String {
        let mut out = String::with_capacity(Self::TOTAL_DIGITS + (Self::GROUPS - 1));
        for i in 0..Self::GROUPS {
            if i > 0 {
                out.push('-');
            }
            let v = u16::from_be_bytes([self.0[i * 2], self.0[i * 2 + 1]]);
            let n = (v as u32) * 11;
            // n is in [0, 720885], always fits in 6 decimal digits.
            out.push_str(&format!("{:06}", n));
        }
        out
    }

    /// Display form: 4 rows of 4 groups, '\n' between rows, '-' within a row.
    pub fn encode_for_display(&self) -> String {
        let flat = self.encode();
        let groups: Vec<&str> = flat.split('-').collect();
        groups
            .chunks(4)
            .map(|row| row.join("-"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn decode(s: &str) -> Result<Self> {
        let mut cleaned = String::with_capacity(Self::TOTAL_DIGITS);
        for c in s.chars() {
            if c.is_whitespace() || c == '-' || c == '.' {
                continue;
            }
            cleaned.push(c);
        }
        if cleaned.len() != Self::TOTAL_DIGITS {
            return Err(Error::RecoveryKey(format!(
                "expected {} digits after stripping separators, got {}",
                Self::TOTAL_DIGITS,
                cleaned.len()
            )));
        }
        if !cleaned.chars().all(|c| c.is_ascii_digit()) {
            return Err(Error::RecoveryKey(
                "contains non-digit characters after stripping separators".into(),
            ));
        }

        let mut bytes = [0u8; 32];
        for i in 0..Self::GROUPS {
            let start = i * Self::DIGITS_PER_GROUP;
            let end = start + Self::DIGITS_PER_GROUP;
            let group: u32 = cleaned[start..end].parse().map_err(|_| {
                Error::RecoveryKey(format!("group {} is not a valid number", i + 1))
            })?;
            if group % 11 != 0 {
                return Err(Error::RecoveryKey(format!(
                    "group {} fails check digit (not divisible by 11)",
                    i + 1
                )));
            }
            let v = group / 11;
            if v > u16::MAX as u32 {
                return Err(Error::RecoveryKey(format!(
                    "group {} value {} exceeds u16 range",
                    i + 1,
                    v
                )));
            }
            let be = (v as u16).to_be_bytes();
            bytes[i * 2] = be[0];
            bytes[i * 2 + 1] = be[1];
        }
        Ok(Self(bytes))
    }
}

impl Zeroize for RecoveryKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RecoveryKey(<32 bytes redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_zeros() {
        let k = RecoveryKey::from_bytes([0u8; 32]);
        let encoded = k.encode();
        // 16 groups of "000000" joined by '-'
        assert_eq!(encoded, vec!["000000"; 16].join("-"));
        let decoded = RecoveryKey::decode(&encoded).unwrap();
        assert_eq!(decoded.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn round_trip_max() {
        let k = RecoveryKey::from_bytes([0xFFu8; 32]);
        let encoded = k.encode();
        // Each group: 65535 * 11 = 720885
        assert_eq!(encoded, vec!["720885"; 16].join("-"));
        let decoded = RecoveryKey::decode(&encoded).unwrap();
        assert_eq!(decoded.as_bytes(), &[0xFFu8; 32]);
    }

    #[test]
    fn round_trip_many_random() {
        for _ in 0..256 {
            let k = RecoveryKey::generate().unwrap();
            let encoded = k.encode();
            let decoded = RecoveryKey::decode(&encoded).unwrap();
            assert_eq!(decoded.as_bytes(), k.as_bytes());
        }
    }

    #[test]
    fn every_group_is_divisible_by_11() {
        for _ in 0..32 {
            let k = RecoveryKey::generate().unwrap();
            for group in k.encode().split('-') {
                let n: u32 = group.parse().unwrap();
                assert_eq!(n % 11, 0, "group {} not divisible by 11", group);
                assert_eq!(group.len(), 6, "group not exactly 6 digits");
            }
        }
    }

    #[test]
    fn display_form_has_4_rows_of_4() {
        let k = RecoveryKey::generate().unwrap();
        let disp = k.encode_for_display();
        let rows: Vec<&str> = disp.split('\n').collect();
        assert_eq!(rows.len(), 4);
        for row in rows {
            assert_eq!(row.split('-').count(), 4);
        }
        // Display form must round-trip via the liberal parser.
        let decoded = RecoveryKey::decode(&disp).unwrap();
        assert_eq!(decoded.as_bytes(), k.as_bytes());
    }

    #[test]
    fn liberal_parser_accepts_whitespace_and_dashes() {
        let k = RecoveryKey::generate().unwrap();
        let canonical = k.encode();
        // Sprinkle in extra whitespace, dashes, dots, newlines.
        let messy = format!("  {}  \n", canonical.replace('-', " -- "));
        let decoded = RecoveryKey::decode(&messy).unwrap();
        assert_eq!(decoded.as_bytes(), k.as_bytes());
    }

    #[test]
    fn rejects_wrong_length() {
        // 95 digits instead of 96.
        let s = "0".repeat(95);
        assert!(matches!(
            RecoveryKey::decode(&s).unwrap_err(),
            Error::RecoveryKey(_)
        ));
    }

    #[test]
    fn rejects_non_digit() {
        let mut s = "0".repeat(96);
        s.replace_range(10..11, "x");
        assert!(matches!(
            RecoveryKey::decode(&s).unwrap_err(),
            Error::RecoveryKey(_)
        ));
    }

    #[test]
    fn rejects_bad_check_digit() {
        // All-zeros key, then bump the very last digit by 1 → group becomes 000001,
        // which is not divisible by 11.
        let mut s = vec!["000000"; 16].join("-");
        let last = s.len() - 1;
        s.replace_range(last..last + 1, "1");
        assert!(matches!(
            RecoveryKey::decode(&s).unwrap_err(),
            Error::RecoveryKey(_)
        ));
    }

    #[test]
    fn single_digit_flips_caught_with_high_probability() {
        // For each randomly chosen single-digit flip, the check digit should
        // catch it ~10/11 of the time. Across many trials we expect well over
        // 90% detection.
        let mut detected = 0;
        let mut trials = 0;
        for _ in 0..200 {
            let k = RecoveryKey::generate().unwrap();
            let encoded = k.encode();
            let bytes = encoded.as_bytes();
            // Pick a random digit position.
            let mut idx_buf = [0u8; 1];
            getrandom::getrandom(&mut idx_buf).unwrap();
            let mut pos = (idx_buf[0] as usize) % bytes.len();
            // Skip dash positions.
            while bytes[pos] == b'-' {
                pos = (pos + 1) % bytes.len();
            }
            let original = bytes[pos];
            // Flip to a different digit.
            let mut delta_buf = [0u8; 1];
            getrandom::getrandom(&mut delta_buf).unwrap();
            let delta = (delta_buf[0] % 9) + 1;
            let new_digit = b'0' + ((original - b'0' + delta) % 10);
            let mut mutated = encoded.into_bytes();
            mutated[pos] = new_digit;
            let mutated_s = String::from_utf8(mutated).unwrap();
            trials += 1;
            if RecoveryKey::decode(&mutated_s).is_err() {
                detected += 1;
            }
        }
        // Theoretical lower bound is roughly 90%; we use 80% to avoid flakes.
        assert!(
            detected * 100 / trials >= 80,
            "single-digit flip detection too low: {}/{}",
            detected,
            trials
        );
    }

    #[test]
    fn debug_redacts_contents() {
        let k = RecoveryKey::generate().unwrap();
        let dbg = format!("{:?}", k);
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains(&k.encode()[..6]));
    }
}
