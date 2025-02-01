import random
import secrets
import string

import pytest
from fastfpe import ff3_1
from ff3 import FF3Cipher


@pytest.fixture
def pyff3_setup():
    key = secrets.token_hex()
    tweak = secrets.token_hex(7)
    alphabet = string.digits + string.ascii_lowercase + string.ascii_uppercase
    plaintext = "".join(random.choices(alphabet, k=12))

    py_cipher = FF3Cipher.withCustomAlphabet(key, tweak, alphabet)
    return py_cipher, plaintext


@pytest.fixture
def rustff3_setup():
    key = secrets.token_hex()
    tweak = secrets.token_hex(7)
    alphabet = string.digits + string.ascii_lowercase + string.ascii_uppercase
    plaintext = "".join(random.choices(alphabet, k=12))

    return key, tweak, alphabet, plaintext


def pyff3(cipher, plaintext):
    assert cipher.decrypt(cipher.encrypt(plaintext)) == plaintext


def rustff3(key, tweak, alphabet, plaintext):
    assert (
        ff3_1.decrypt(key, tweak, alphabet, ff3_1.encrypt(key, tweak, alphabet, plaintext))
        == plaintext
    )


@pytest.mark.skip()
def test_bench_pyff3(pyff3_setup, benchmark):
    py_cipher, plaintext = pyff3_setup
    benchmark(pyff3, py_cipher, plaintext)


@pytest.mark.skip()
def test_bench_rustff3(rustff3_setup, benchmark):
    key, tweak, alphabet, plaintext = rustff3_setup
    benchmark(rustff3, key, tweak, alphabet, plaintext)
