import math
import string

from fastfpe import ff1
from hypothesis import given
from hypothesis import strategies as st


@st.composite
def ff1_examples(draw):
    key_len = draw(st.sampled_from([16, 24, 32]))
    key = draw(st.binary(min_size=key_len, max_size=key_len)).hex()

    # FF1 tweak can be empty or arbitrary length; constrain to <= 16 for tests
    tweak_len = draw(st.integers(min_value=0, max_value=16))
    tweak = draw(st.binary(min_size=tweak_len, max_size=tweak_len)).hex()

    pool = list(string.digits + string.ascii_lowercase)
    alpha_list = draw(st.lists(st.sampled_from(pool), min_size=2, max_size=30, unique=True))
    alphabet = "".join(alpha_list)

    radix = len(alphabet)
    min_len = math.ceil(6 / math.log10(radix))
    # FF1 supports very long inputs; cap for test performance
    pt_len = draw(st.integers(min_value=min_len, max_value=1024))
    pt = "".join(draw(st.lists(st.sampled_from(list(alphabet)), min_size=pt_len, max_size=pt_len)))

    return key, tweak, alphabet, pt


@given(ff1_examples())
def test_ff1_hypothesis_roundtrip(example):
    key, tweak, alphabet, pt = example
    ct = ff1.encrypt(key, tweak, alphabet, pt)
    assert ff1.decrypt(key, tweak, alphabet, ct) == pt
