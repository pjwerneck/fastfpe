use pyo3::{exceptions::PyValueError, prelude::*};

mod ff3_1;

#[pyfunction]
#[pyo3(text_signature = "(key, tweak, alphabet, plaintext)")]
/// Encrypts plaintext using FF3-1 format-preserving encryption
///
/// Args:
///     key (str): Hex-encoded AES key (16, 24, or 32 bytes after decoding)
///     tweak (str): Hex-encoded tweak (7 or 8 bytes after decoding)
///     alphabet (str): String containing the valid characters
///     plaintext (str): Text to encrypt, must contain only characters from alphabet
///
/// Returns:
///     str: The encrypted text
///
/// Raises:
///     ValueError: If inputs are invalid
fn ff3_1_encrypt(
    py: Python,
    key: &str,
    tweak: &str,
    alphabet: &str,
    plaintext: &str,
) -> PyResult<String> {
    py.allow_threads(|| {
        ff3_1::encrypt(key, tweak, alphabet, plaintext).map_err(|e| PyValueError::new_err(e))
    })
}

#[pyfunction]
#[pyo3(text_signature = "(key, tweak, alphabet, ciphertext)")]
/// Decrypts ciphertext using FF3-1 format-preserving encryption
///
/// Args:
///     key (str): Hex-encoded AES key (16, 24, or 32 bytes after decoding)
///     tweak (str): Hex-encoded tweak (7 or 8 bytes after decoding)
///     alphabet (str): String containing the valid characters
///     ciphertext (str): Text to decrypt, must contain only characters from alphabet
///
/// Returns:
///     str: The decrypted text
///
/// Raises:
///     ValueError: If inputs are invalid
fn ff3_1_decrypt(
    py: Python,
    key: &str,
    tweak: &str,
    alphabet: &str,
    ciphertext: &str,
) -> PyResult<String> {
    py.allow_threads(|| {
        ff3_1::decrypt(key, tweak, alphabet, ciphertext).map_err(|e| PyValueError::new_err(e))
    })
}

#[pymodule]
fn _rust_fastfpe(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(ff3_1_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(ff3_1_decrypt, m)?)?;
    Ok(())
}
