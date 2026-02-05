use fpe::ff1;

pub fn encrypt(key: &str, tweak: &str, alphabet: &str, plaintext: &str) -> Result<String, String> {
    let key_bytes = hex::decode(key).map_err(|e| format!("Invalid key hex: {e}"))?;
    let tweak_bytes = if tweak.is_empty() {
        vec![]
    } else {
        hex::decode(tweak).map_err(|e| format!("Invalid tweak hex: {e}"))?
    };
    let radix = alphabet.chars().count();

    ff1::encrypt(
        &key_bytes,
        Some(&tweak_bytes),
        plaintext,
        radix,
        Some(alphabet),
    )
    .map_err(|e| format!("Encryption failed: {e}"))
}

pub fn decrypt(key: &str, tweak: &str, alphabet: &str, ciphertext: &str) -> Result<String, String> {
    let key_bytes = hex::decode(key).map_err(|e| format!("Invalid key hex: {e}"))?;
    let tweak_bytes = if tweak.is_empty() {
        vec![]
    } else {
        hex::decode(tweak).map_err(|e| format!("Invalid tweak hex: {e}"))?
    };
    let radix = alphabet.chars().count();

    ff1::decrypt(
        &key_bytes,
        Some(&tweak_bytes),
        ciphertext,
        radix,
        Some(alphabet),
    )
    .map_err(|e| format!("Decryption failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_vector() {
        let key = "2b7e151628aed2a6abf7158809cf4f3c"; // 128-bit
        let tweak = ""; // empty allowed
        let alphabet = "0123456789";
        let pt = "0123456789";
        let ct = encrypt(key, tweak, alphabet, pt).unwrap();
        assert_eq!(ct, "2433477484");
        assert_eq!(decrypt(key, tweak, alphabet, &ct).unwrap(), pt);
    }

    #[test]
    fn roundtrip_various_key_sizes() {
        let tweak = "00010203"; // 4 bytes
        let alphabet = "0123456789abcdef";
        let pt = "feedface";

        // 128-bit
        let k128 = "000102030405060708090a0b0c0d0e0f";
        let ct128 = encrypt(k128, tweak, alphabet, pt).unwrap();
        assert_eq!(decrypt(k128, tweak, alphabet, &ct128).unwrap(), pt);

        // 192-bit
        let k192 = "000102030405060708090a0b0c0d0e0f1011121314151617";
        let ct192 = encrypt(k192, tweak, alphabet, pt).unwrap();
        assert_eq!(decrypt(k192, tweak, alphabet, &ct192).unwrap(), pt);

        // 256-bit
        let k256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let ct256 = encrypt(k256, tweak, alphabet, pt).unwrap();
        assert_eq!(decrypt(k256, tweak, alphabet, &ct256).unwrap(), pt);
    }

    #[test]
    fn invalid_key_hex() {
        let key = "zz"; // invalid hex
        let tweak = "";
        let alphabet = "0123456789";
        let pt = "0123";
        let err = encrypt(key, tweak, alphabet, pt).unwrap_err();
        assert!(err.to_lowercase().contains("key"));
    }

    #[test]
    fn invalid_tweak_hex() {
        let key = "2b7e151628aed2a6abf7158809cf4f3c";
        let tweak = "xx"; // invalid hex
        let alphabet = "0123456789";
        let pt = "0123";
        let err = encrypt(key, tweak, alphabet, pt).unwrap_err();
        assert!(err.to_lowercase().contains("tweak"));
    }

    #[test]
    fn invalid_tweak_length() {
        // FF1 allows variable-length tweaks; this test ensures even long tweaks work.
        let key = "2b7e151628aed2a6abf7158809cf4f3c";
        let alphabet = "0123456789";
        let pt = "0123456789";
        let long_tweak = "00".repeat(128); // 128 bytes
        let ct = encrypt(key, &long_tweak, alphabet, pt).unwrap();
        assert_eq!(decrypt(key, &long_tweak, alphabet, &ct).unwrap(), pt);
    }
}
