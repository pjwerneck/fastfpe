import pytest
from fastfpe import ff1


def test_ff1_kat_from_docs():
    # Known-answer from crate docs
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    tweak = ""  # empty tweak
    alphabet = "0123456789"
    pt = "0123456789"
    ct = ff1.encrypt(key, tweak, alphabet, pt)
    assert ct == "2433477484"
    assert ff1.decrypt(key, tweak, alphabet, ct) == pt


def test_ff1_key_sizes_roundtrip():
    keys = ["00" * 16, "11" * 24, "22" * 32]
    tweak = ""
    alphabet = "0123456789"
    pt = "123456789012"
    for k in keys:
        ct = ff1.encrypt(k, tweak, alphabet, pt)
        assert ff1.decrypt(k, tweak, alphabet, ct) == pt


def test_ff1_invalid_alphabet_duplicate():
    key = "00" * 16
    tweak = ""
    alphabet = "0012345"  # duplicate 0
    with pytest.raises(ValueError):
        ff1.encrypt(key, tweak, alphabet, "012345")


def test_ff1_length_bounds_radix10():
    key = "00" * 16
    tweak = ""
    alphabet = "0123456789"
    ok_min = "0" * 6
    ok_long = "1" * 64  # still allowed for FF1
    bad_short = "0" * 5

    ct = ff1.encrypt(key, tweak, alphabet, ok_min)
    assert ff1.decrypt(key, tweak, alphabet, ct) == ok_min

    ct = ff1.encrypt(key, tweak, alphabet, ok_long)
    assert ff1.decrypt(key, tweak, alphabet, ct) == ok_long

    with pytest.raises(ValueError):
        ff1.encrypt(key, tweak, alphabet, bad_short)


def test_ff1_non_ascii_accented_chars():
    """Test encryption/decryption with accented characters."""
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    tweak = ""
    alphabet = "abcdefghijklmnopqrstuvwxyzàáâãäåèéêëìíîïòóôõöùúûü"
    pt = "héllòwörld"
    ct = ff1.encrypt(key, tweak, alphabet, pt)
    assert ct != pt  # Should be encrypted
    assert len(ct) == len(pt)  # Length preserved
    assert ff1.decrypt(key, tweak, alphabet, ct) == pt


def test_ff1_non_ascii_cyrillic():
    """Test encryption/decryption with Cyrillic characters."""
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    tweak = ""
    alphabet = "абвгдежзийклмнопрстуфхцчшщъыьэюя"
    pt = "привет"
    ct = ff1.encrypt(key, tweak, alphabet, pt)
    assert ct != pt
    assert len(ct) == len(pt)
    assert ff1.decrypt(key, tweak, alphabet, ct) == pt


def test_ff1_non_ascii_chinese():
    """Test encryption/decryption with Chinese characters."""
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    tweak = ""
    alphabet = "零一二三四五六七八九十百千万"
    pt = "一二三四五六"
    ct = ff1.encrypt(key, tweak, alphabet, pt)
    assert ct != pt
    assert len(ct) == len(pt)
    assert ff1.decrypt(key, tweak, alphabet, ct) == pt


def test_ff1_non_ascii_mixed_unicode():
    """Test encryption/decryption with mixed Unicode characters."""
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    tweak = ""
    # Mix of Latin, Greek, and special chars
    alphabet = "αβγδεζηθικλμνξοπρστυφχψω0123456789"
    pt = "α1β2γ3δ4ε5ζ6"
    ct = ff1.encrypt(key, tweak, alphabet, pt)
    assert ct != pt
    assert len(ct) == len(pt)
    assert ff1.decrypt(key, tweak, alphabet, ct) == pt


def test_ff1_non_ascii_emoji():
    """Test encryption/decryption with emoji characters."""
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    tweak = ""
    alphabet = "😀😁😂🤣😃😄😅😆😉😊"
    pt = "😀😁😂🤣😃😊"
    ct = ff1.encrypt(key, tweak, alphabet, pt)
    assert ct != pt
    assert len(ct) == len(pt)
    assert ff1.decrypt(key, tweak, alphabet, ct) == pt


def test_ff1_non_ascii_arabic():
    """Test encryption/decryption with Arabic characters."""
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    tweak = ""
    alphabet = "ابتثجحخدذرزسشصضطظعغفقكلمنهوي"
    pt = "مرحبابك"
    ct = ff1.encrypt(key, tweak, alphabet, pt)
    assert ct != pt
    assert len(ct) == len(pt)
    assert ff1.decrypt(key, tweak, alphabet, ct) == pt


def test_ff1_non_ascii_japanese_hiragana():
    """Test encryption/decryption with Japanese Hiragana characters."""
    key = "2b7e151628aed2a6abf7158809cf4f3c"
    tweak = ""
    alphabet = "あいうえおかきくけこさしすせそたちつてと"
    pt = "あいうえおか"  # Uses only characters from the alphabet
    ct = ff1.encrypt(key, tweak, alphabet, pt)
    assert ct != pt
    assert len(ct) == len(pt)
    assert ff1.decrypt(key, tweak, alphabet, ct) == pt


def test_ff1_non_ascii_roundtrip_comprehensive():
    """Comprehensive test with various non-ASCII alphabets."""
    key = "00" * 16
    tweak = "1234567890abcdef"

    test_cases = [
        # (alphabet, plaintext) - each alphabet has 10+ unique chars, plaintext >= 6 chars
        ("äöüßÄÖÜéèê", "äöüßäöüÄÖÜ"),  # German extended (10 chars)
        ("ñáéíóúÑÁÉÍÓÚ", "ñáéíóúñáéí"),  # Spanish (12 chars)
        ("àâæçéèêëïîôùûüÿ", "çàéèêëîôïû"),  # French (15 chars)
        ("가나다라마바사아자차카타파하", "가나다라마바사아"),  # Korean (14 chars)
        ("₹€£¥₽₩₿₸₺₼", "₹€£¥₽₩₿₸₺₼"),  # Currency symbols (10 chars)
    ]

    for alphabet, pt in test_cases:
        ct = ff1.encrypt(key, tweak, alphabet, pt)
        decrypted = ff1.decrypt(key, tweak, alphabet, ct)
        assert decrypted == pt, f"Failed for alphabet: {alphabet}, plaintext: {pt}"
