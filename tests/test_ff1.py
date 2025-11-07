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
