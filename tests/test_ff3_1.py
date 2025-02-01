import pytest
from fastfpe import ff3_1
from ff3 import FF3Cipher

# check fastfpe.ff3_1 against ff3.FF3Cipher


def test_against_python_reference():
    key = "00112233445566778899aabbccddeeff"
    tweak = "abcdef12345678"  # Note: 7 bytes for FF3-1
    alphabet = "abcdef0123456789"
    plaintext = "12345678"

    # Test using Python reference implementation
    py_cipher = FF3Cipher.withCustomAlphabet(key, tweak, alphabet)
    py_ciphertext = py_cipher.encrypt(plaintext)
    py_decrypted = py_cipher.decrypt(py_ciphertext)

    # Test using our Rust implementation
    rust_ciphertext = ff3_1.encrypt(key, tweak, alphabet, plaintext)
    rust_decrypted = ff3_1.decrypt(key, tweak, alphabet, rust_ciphertext)

    assert rust_ciphertext == py_ciphertext
    assert rust_decrypted == py_decrypted
    assert rust_decrypted == plaintext


def test_various_lengths():
    key = "2B7E151628AED2A6ABF7158809CF4F3C"
    tweak = "CBD09280979564"
    alphabet = "0123456789"
    test_cases = [
        "0123456789",
        "123456789",
        "12345678901234",
        "123456789012345678",
    ]

    py_cipher = FF3Cipher.withCustomAlphabet(key, tweak, alphabet)

    for plaintext in test_cases:
        # Python reference
        py_ciphertext = py_cipher.encrypt(plaintext)
        py_decrypted = py_cipher.decrypt(py_ciphertext)

        # Our Rust implementation
        rust_ciphertext = ff3_1.encrypt(key, tweak, alphabet, plaintext)
        rust_decrypted = ff3_1.decrypt(key, tweak, alphabet, rust_ciphertext)

        assert rust_ciphertext == py_ciphertext
        assert rust_decrypted == py_decrypted
        assert rust_decrypted == plaintext


def test_error_cases():
    key = "00112233445566778899aabbccddeeff"
    tweak = "abcdef1234567"
    alphabet = "0123456789"

    # Test invalid key
    with pytest.raises(ValueError):
        ff3_1.encrypt("invalid", tweak, alphabet, "12345")

    # Test invalid tweak
    with pytest.raises(ValueError):
        ff3_1.encrypt(key, "invalid", alphabet, "12345")

    # Test invalid characters in plaintext
    with pytest.raises(ValueError):
        ff3_1.encrypt(key, tweak, alphabet, "123abc")
