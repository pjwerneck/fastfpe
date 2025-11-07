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


def test_key_sizes_and_roundtrip():
    # 16, 24, 32 bytes keys
    keys = [
        "00" * 16,
        "11" * 24,
        "22" * 32,
    ]
    tweak = "aa" * 7  # 7 bytes
    alphabet = "0123456789"
    pt = "123456789012"  # length >= 6

    for key in keys:
        ct = ff3_1.encrypt(key, tweak, alphabet, pt)
        assert ct != pt
        assert ff3_1.decrypt(key, tweak, alphabet, ct) == pt


def test_tweak_length_validation():
    key = "00" * 16
    alphabet = "0123456789"
    pt = "123456"

    # valid 7-byte tweak
    tweak7 = "ab" * 7
    ct = ff3_1.encrypt(key, tweak7, alphabet, pt)
    assert ff3_1.decrypt(key, tweak7, alphabet, ct) == pt

    # invalid 8-byte tweak should raise
    tweak8 = "cd" * 8
    with pytest.raises(ValueError):
        ff3_1.encrypt(key, tweak8, alphabet, pt)


def test_alphabet_duplicates():
    key = "00" * 16
    tweak = "ab" * 7
    # duplicate '0' and '1'
    alphabet = "0123401234"
    with pytest.raises(ValueError):
        ff3_1.encrypt(key, tweak, alphabet, "012345")


def test_min_max_length_radix10():
    key = "00" * 16
    tweak = "ab" * 7
    alphabet = "0123456789"

    # For radix 10: min = 6, max ≈ 57 (floor(192/log2(10)))
    ok_min = "1" * 6
    ok_max = "1" * 57
    too_short = "1" * 5
    too_long = "1" * 58

    # boundaries pass
    ct = ff3_1.encrypt(key, tweak, alphabet, ok_min)
    assert ff3_1.decrypt(key, tweak, alphabet, ct) == ok_min

    ct = ff3_1.encrypt(key, tweak, alphabet, ok_max)
    assert ff3_1.decrypt(key, tweak, alphabet, ct) == ok_max

    # outside boundaries fail
    with pytest.raises(ValueError):
        ff3_1.encrypt(key, tweak, alphabet, too_short)
    with pytest.raises(ValueError):
        ff3_1.encrypt(key, tweak, alphabet, too_long)


def test_min_length_binary_alphabet():
    key = "00" * 16
    tweak = "ab" * 7
    alphabet = "01"

    # For radix 2: min = ceil(6/log10(2)) = 20
    ok = "01" * 10  # 20
    bad = "01" * 9 + "0"  # 19

    ct = ff3_1.encrypt(key, tweak, alphabet, ok)
    assert ff3_1.decrypt(key, tweak, alphabet, ct) == ok

    with pytest.raises(ValueError):
        ff3_1.encrypt(key, tweak, alphabet, bad)


def test_wrong_tweak_changes_output():
    key = "00" * 16
    tweak_a = "12" * 7
    tweak_b = "34" * 7
    alphabet = "0123456789abcdef"
    pt = "abcdef12"

    ct = ff3_1.encrypt(key, tweak_a, alphabet, pt)
    # decryption with a different tweak should not recover plaintext
    dec = ff3_1.decrypt(key, tweak_b, alphabet, ct)
    assert dec != pt
