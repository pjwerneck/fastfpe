import string

from fastfpe import ff3_1
from ff3 import FF3Cipher
from hypothesis import given
from hypothesis import strategies as st

# Unicode character pools for testing multi-byte character handling
UNICODE_EXTRAS = (
    "àáâãäåèéêëìíîïòóôõöùúûü"  # Accented Latin
    "αβγδεζηθικλμνξοπρστυφχψω"  # Greek
    "абвгдежзийклмнопрстуфхцчшщъыьэюя"  # Cyrillic
    "零一二三四五六七八九"  # Chinese numerals
    "あいうえおかきくけこ"  # Japanese Hiragana
)


@st.composite
def ff3_examples(draw):
    # key bytes: 16,24,32
    key_len = draw(st.sampled_from([16, 24, 32]))
    key = draw(st.binary(min_size=key_len, max_size=key_len)).hex()

    # tweak must be exactly 7 bytes
    tweak = draw(st.binary(min_size=7, max_size=7)).hex()

    # alphabet: unique characters sampled from digits+lowercase+unicode
    pool = list(string.digits + string.ascii_lowercase + UNICODE_EXTRAS)
    alpha_list = draw(st.lists(st.sampled_from(pool), min_size=2, max_size=20, unique=True))
    alphabet = "".join(alpha_list)

    # Use the reference implementation's computed bounds to avoid sampling invalid lengths
    ref_cipher = FF3Cipher.withCustomAlphabet(key, tweak, alphabet)
    min_len = ref_cipher.minLen
    max_len = ref_cipher.maxLen

    pt_len = draw(st.integers(min_value=min_len, max_value=max_len))
    pt = "".join(draw(st.lists(st.sampled_from(list(alphabet)), min_size=pt_len, max_size=pt_len)))

    return key, tweak, alphabet, pt


@given(ff3_examples())
def test_hypothesis_roundtrip(example):
    key, tweak, alphabet, pt = example
    ct = ff3_1.encrypt(key, tweak, alphabet, pt)
    assert ff3_1.decrypt(key, tweak, alphabet, ct) == pt

    # cross-check against Python reference implementation
    py = FF3Cipher.withCustomAlphabet(key, tweak, alphabet)
    assert py.decrypt(py.encrypt(pt)) == pt
    assert ct == py.encrypt(pt)
