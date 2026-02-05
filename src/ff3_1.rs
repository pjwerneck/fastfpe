use fpe::ff3_1;

pub fn encrypt(key: &str, tweak: &str, alphabet: &str, plaintext: &str) -> Result<String, String> {
    let key_bytes = hex::decode(key).map_err(|e| format!("Invalid key hex: {e}"))?;
    let tweak_bytes = hex::decode(tweak).map_err(|e| format!("Invalid tweak hex: {e}"))?;
    let radix = alphabet.chars().count();

    ff3_1::encrypt(
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
    let tweak_bytes = hex::decode(tweak).map_err(|e| format!("Invalid tweak hex: {e}"))?;
    let radix = alphabet.chars().count();

    ff3_1::decrypt(
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
        let key = "00112233445566778899aabbccddeeff";
        let tweak = "abcdef12345678";
        let alphabet = "abcdef0123456789";
        let plaintext = "12345678";

        let ciphertext = encrypt(key, tweak, alphabet, plaintext).unwrap();
        let decrypted = decrypt(key, tweak, alphabet, &ciphertext).unwrap();

        assert_eq!(ciphertext, "cf64ccfe");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn roundtrip_various_key_sizes() {
        let alphabet = "0123456789abcdef";
        let tweak = "00112233445566"; // 7 bytes
        let pt = "deadbeef";

        // 128-bit key
        let k128 = "000102030405060708090a0b0c0d0e0f";
        let ct128 = encrypt(k128, tweak, alphabet, pt).unwrap();
        assert_eq!(decrypt(k128, tweak, alphabet, &ct128).unwrap(), pt);

        // 192-bit key
        let k192 = "000102030405060708090a0b0c0d0e0f1011121314151617";
        let ct192 = encrypt(k192, tweak, alphabet, pt).unwrap();
        assert_eq!(decrypt(k192, tweak, alphabet, &ct192).unwrap(), pt);

        // 256-bit key
        let k256 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        let ct256 = encrypt(k256, tweak, alphabet, pt).unwrap();
        assert_eq!(decrypt(k256, tweak, alphabet, &ct256).unwrap(), pt);
    }

    #[test]
    fn invalid_tweak_length() {
        let key = "00112233445566778899aabbccddeeff";
        let alphabet = "0123456789abcdef";
        let pt = "01234567";
        // 6 bytes (invalid)
        let bad_tweak = "001122334455";
        let err = encrypt(key, bad_tweak, alphabet, pt).unwrap_err();
        assert!(err.to_lowercase().contains("tweak"));
    }

    #[test]
    fn invalid_key_hex() {
        let key = "not-hex";
        let tweak = "00112233445566";
        let alphabet = "0123456789";
        let pt = "012345";
        let err = encrypt(key, tweak, alphabet, pt).unwrap_err();
        assert!(err.to_lowercase().contains("key"));
    }

    #[test]
    fn invalid_tweak_hex() {
        let key = "00112233445566778899aabbccddeeff";
        let tweak = "zz"; // invalid hex
        let alphabet = "0123456789";
        let pt = "012345";
        let err = encrypt(key, tweak, alphabet, pt).unwrap_err();
        assert!(err.to_lowercase().contains("tweak"));
    }
}
