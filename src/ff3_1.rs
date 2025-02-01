use fpe::ff3_1;

pub fn encrypt(key: &str, tweak: &str, alphabet: &str, plaintext: &str) -> Result<String, String> {
    let key_bytes = hex::decode(key).map_err(|e| format!("Invalid key hex: {}", e))?;
    let tweak_bytes = hex::decode(tweak).map_err(|e| format!("Invalid tweak hex: {}", e))?;
    let radix = alphabet.len();

    ff3_1::encrypt(
        &key_bytes,
        Some(&tweak_bytes),
        plaintext,
        radix,
        Some(alphabet),
    )
    .map_err(|e| format!("{:?}", e))
}

pub fn decrypt(key: &str, tweak: &str, alphabet: &str, ciphertext: &str) -> Result<String, String> {
    let key_bytes = hex::decode(key).map_err(|e| format!("Invalid key hex: {}", e))?;
    let tweak_bytes = hex::decode(tweak).map_err(|e| format!("Invalid tweak hex: {}", e))?;
    let radix = alphabet.len();

    ff3_1::decrypt(
        &key_bytes,
        Some(&tweak_bytes),
        ciphertext,
        radix,
        Some(alphabet),
    )
    .map_err(|e| format!("{:?}", e))
}

#[test]
fn test_ff3_1_reference() {
    let key = "00112233445566778899aabbccddeeff";
    let tweak = "abcdef12345678";
    let alphabet = "abcdef0123456789";
    let plaintext = "12345678";

    let ciphertext = encrypt(key, tweak, alphabet, plaintext).unwrap();
    let decrypted = decrypt(key, tweak, alphabet, &ciphertext).unwrap();

    assert_eq!(ciphertext, "cf64ccfe");
    assert_eq!(decrypted, plaintext);
}
