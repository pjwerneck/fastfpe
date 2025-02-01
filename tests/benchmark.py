import timeit
from statistics import mean
from statistics import stdev

setup = """
import secrets
import string
import random

key = secrets.token_hex()
tweak = secrets.token_hex(7)
alphabet = string.digits + string.ascii_lowercase + string.ascii_uppercase
plaintext = "".join(random.choices(alphabet, k={k}))

"""

py_setup = f"""
from ff3 import FF3Cipher
{setup}
py_cipher = FF3Cipher.withCustomAlphabet(key, tweak, alphabet)
"""

rust_setup = f"""
from fastfpe import ff3_1
{setup}
"""


py_test = "assert py_cipher.decrypt(py_cipher.encrypt(plaintext)) == plaintext"
rust_test = "assert ff3_1.decrypt(key, tweak, alphabet, ff3_1.encrypt(key, tweak, alphabet, plaintext)) == plaintext"


def run_benchmark(stmt, setup, number=1000, repeat=5):
    times = timeit.repeat(stmt=stmt, setup=setup, number=number, repeat=repeat)
    avg_time = mean(times)
    std_time = stdev(times)
    per_op = avg_time / number * 1000  # ms per operation

    return per_op, std_time / number * 1000


if __name__ == "__main__":
    number = 10000
    pt_length = [12, 16, 20, 24]
    repeat = 5

    for k in pt_length:
        print(f"\nRunning {number:,} iterations, {repeat} times each, {k}-byte plaintext")
        print("-" * 50)

        py_time, py_std = run_benchmark(
            py_test, py_setup.format(k=k), number=number, repeat=repeat
        )
        rust_time, rust_std = run_benchmark(
            rust_test, rust_setup.format(k=k), number=number, repeat=repeat
        )

        print(f"\nPython implementation: {py_time:.3f} ms/op (± {py_std:.3f} ms)")
        print(f"Rust implementation:   {rust_time:.3f} ms/op (± {rust_std:.3f} ms)")
        print(f"Rust is {py_time / rust_time:.1f}x faster")
