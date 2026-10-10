use hmac::{Hmac, Mac};
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::{OsmanthusError, Result};

const STEP_SECONDS: i64 = 30;
const DIGITS_MODULUS: u32 = 1_000_000;

pub fn verify_code(secret_base32: &str, code: &str, unix_time: i64) -> Result<Option<u64>> {
    let normalized = code.trim();
    if normalized.len() != 6 || !normalized.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(None);
    }
    let secret = Zeroizing::new(
        data_encoding::BASE32_NOPAD
            .decode(secret_base32.as_bytes())
            .map_err(|error| {
                OsmanthusError::InvalidState(format!("invalid TOTP secret: {error}"))
            })?,
    );
    let current = unix_time.div_euclid(STEP_SECONDS);
    for offset in [-1_i64, 0, 1] {
        let candidate = current + offset;
        if candidate < 0 {
            continue;
        }
        let expected = Zeroizing::new(format!("{:06}", generate(&secret, candidate as u64)?));
        if constant_time_equal(expected.as_bytes(), normalized.as_bytes()) {
            return Ok(Some(candidate as u64));
        }
    }
    Ok(None)
}

pub fn code_at(secret_base32: &str, unix_time: i64) -> Result<String> {
    let secret = Zeroizing::new(
        data_encoding::BASE32_NOPAD
            .decode(secret_base32.as_bytes())
            .map_err(|error| {
                OsmanthusError::InvalidState(format!("invalid TOTP secret: {error}"))
            })?,
    );
    let counter = unix_time.div_euclid(STEP_SECONDS);
    if counter < 0 {
        return Err(OsmanthusError::InvalidState(
            "system time predates Unix epoch".to_owned(),
        ));
    }
    Ok(format!("{:06}", generate(&secret, counter as u64)?))
}

fn generate(secret: &[u8], counter: u64) -> Result<u32> {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret)
        .map_err(|_| OsmanthusError::InvalidState("invalid TOTP key length".to_owned()))?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    Ok(binary % DIGITS_MODULUS)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc_6238_sha1_vector_after_truncation() {
        let secret = data_encoding::BASE32_NOPAD.encode(b"12345678901234567890");
        assert_eq!(code_at(&secret, 59).unwrap(), "287082");
        assert_eq!(code_at(&secret, 1_111_111_109).unwrap(), "081804");
    }

    #[test]
    fn accepts_only_adjacent_time_steps() {
        let secret = data_encoding::BASE32_NOPAD.encode(b"12345678901234567890");
        let code = code_at(&secret, 60).unwrap();
        assert!(verify_code(&secret, &code, 89).unwrap().is_some());
        assert!(verify_code(&secret, &code, 121).unwrap().is_none());
    }
}
