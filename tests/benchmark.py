import timeit
from statistics import mean
from statistics import stdev

setup = """
from fastfpe import ff3_1
from ff3 import FF3Cipher

key = "00112233445566778899aabbccddeeff"
tweak = "abcdef12345678"
alphabet = "0123456789abcdef"
plaintext = "deadbeef12345678"

py_cipher = FF3Cipher.withCustomAlphabet(key, tweak, alphabet)
"""

py_test = "py_cipher.encrypt(plaintext)"
rust_test = "ff3_1.encrypt(key, tweak, alphabet, plaintext)"


def run_benchmark(stmt, setup, number=1000, repeat=5):
    times = timeit.repeat(stmt=stmt, setup=setup, number=number, repeat=repeat)
    avg_time = mean(times)
    std_time = stdev(times)
    per_op = avg_time / number * 1000  # ms per operation

    return per_op, std_time / number * 1000


if __name__ == "__main__":
    numbers = [100, 1000, 10000]
    repeat = 5

    for number in numbers:
        print(f"\nRunning {number:,} iterations, {repeat} times each")
        print("-" * 50)

        # Just encryption overhead
        setup_only = "from fastfpe import ff3_1; from ff3 import FF3Cipher"
        py_setup_time = timeit.timeit(
            "FF3Cipher.withCustomAlphabet(key, tweak, alphabet)", setup=setup, number=1
        )
        print(f"Python setup time: {py_setup_time * 1000:.3f} ms")

        py_time, py_std = run_benchmark(py_test, setup, number=number, repeat=repeat)
        rust_time, rust_std = run_benchmark(rust_test, setup, number=number, repeat=repeat)

        print(f"\nPython implementation: {py_time:.3f} ms/op (± {py_std:.3f} ms)")
        print(f"Rust implementation:   {rust_time:.3f} ms/op (± {rust_std:.3f} ms)")
        print(f"Rust is {py_time / rust_time:.1f}x faster")

    # Try with longer input
    print("\nTesting with longer input:")
    setup = setup.replace("deadbeef12345678", "deadbeef12345678" * 4)
    # ...rest of the benchmarking code...
