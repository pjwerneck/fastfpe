# fastfpe

 [![Pytest](https://github.com/pjwerneck/fastfpe/actions/workflows/ci.yml/badge.svg)](https://github.com/pjwerneck/fastfpe/actions/workflows/ci.yml)
[![Wheels](https://github.com/pjwerneck/fastfpe/actions/workflows/wheels.yml/badge.svg)](https://github.com/pjwerneck/fastfpe/actions/workflows/wheels.yml)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

Fast Format Preserving Encryption (FPE) implementation in Rust with Python
bindings.

Format-preserving encryption (FPE) is a cryptographic method that encrypts data
while preserving its format. For example, encrypting a credit card number yields
another valid-looking credit card number, making it useful for data protection
while maintaining compatibility with existing systems.


## Features

- FF1 and FF3-1 Format Preserving Encryption algorithms
- Fast Rust implementation with Python bindings
- Support for custom alphabets
- Thread-safe


## Installation

```bash
pip install fastfpe
```
## Usage (FF1)

```python
>>> from fastfpe import ff1
>>>
>>> # 128/192/256-bit AES keys supported (16/24/32 bytes -> 32/48/64 hex chars)
>>> key = "2b7e151628aed2a6abf7158809cf4f3c"  # 128-bit key
>>> tweak = ""  # FF1 tweak may be empty or longer (length impacts security domain sizing)
>>> alphabet = "0123456789"
>>> plaintext = "0123456789"
>>>
>>> ciphertext = ff1.encrypt(key, tweak, alphabet, plaintext)
>>> ciphertext
'2433477484'
>>> ff1.decrypt(key, tweak, alphabet, ciphertext)
'0123456789'
```

Notes:
- FF1 tweak can be empty; size limits depend on NIST SP 800-38G constraints (radix and length bounds enforced internally).
- Provide a non-empty tweak for domain separation across contexts.
- Both algorithms return `ValueError` with descriptive messages on invalid inputs.


## Usage (FF3-1)


> [!WARNING]
> 
> FF3/FF3-1 are no longer recommended in some security guidance due to design
> concerns.
> 
> FF1 is fully supported by fastfpe and recommended for new deployments.
> 
> FF3-1 remains available for compatibility and migration.
>
> See [NIST SP 800-38G](https://csrc.nist.gov/pubs/sp/800/38/g/r1/2pd ) and other sources for details.

```python
>>> from fastfpe import ff3_1
>>>
>>> key = "3eaa133d22a7ee2432fb8ecfde1e97d9106dcf26b9edaa52b3ed4acd9a9b8445"
>>> tweak = "5be49f26c1dbb7"  # 7 bytes (14 hex chars)
>>> alphabet = "abcdef0123456789"
>>> plaintext = "024587931578"
>>>
>>> ciphertext = ff3_1.encrypt(key, tweak, alphabet, plaintext)
>>> ciphertext
'd756b8704a2d'
>>> ff3_1.decrypt(key, tweak, alphabet, ciphertext)
'024587931578'
```


## Performance

As expected, fastfpe is much faster than the reference python implementation.
The gains are more pronounced with larger plaintexts.

The following benchmarks were performed on an Intel(R) Core(TM) i7-8700 CPU @
3.20GHz.


```
Running 10,000 iterations, 5 times each, 12-byte plaintext
--------------------------------------------------

Python implementation: 0.110 ms/op (± 0.001 ms)
Rust implementation:   0.008 ms/op (± 0.000 ms)
Rust is 13.2x faster

Running 10,000 iterations, 5 times each, 16-byte plaintext
--------------------------------------------------

Python implementation: 0.133 ms/op (± 0.002 ms)
Rust implementation:   0.009 ms/op (± 0.000 ms)
Rust is 14.5x faster

Running 10,000 iterations, 5 times each, 20-byte plaintext
--------------------------------------------------

Python implementation: 0.161 ms/op (± 0.005 ms)
Rust implementation:   0.010 ms/op (± 0.002 ms)
Rust is 15.9x faster

Running 10,000 iterations, 5 times each, 24-byte plaintext
--------------------------------------------------

Python implementation: 0.189 ms/op (± 0.004 ms)
Rust implementation:   0.011 ms/op (± 0.000 ms)
Rust is 16.8x faster

```


## Support Matrix

| Component | Versions / Platforms |
|-----------|----------------------|
| Python    | CPython 3.8 – 3.14 (abi3 single wheel per platform) |
| Operating Systems | Linux (x86_64, aarch64 manylinux), macOS (universal2), Windows (x64, arm64) |
| Algorithms | FF1 (recommended), FF3-1 (compatibility) |
| Key Sizes  | 128 / 192 / 256-bit AES |
| Tweak      | FF1: variable length (can be empty). FF3-1: exactly 7 bytes |
| Alphabet   | Custom per call; size defines radix (validated) |

If you need other targets (e.g., musllinux, ppc64le) open an issue or PR.


## License

Licensed under the MIT License. See [LICENSE](LICENSE) for more information.

Uses the [rust-fpe](https://github.com/johntyner/rust-fpe) implementation by
[johntyner](https://github.com/johntyner), under the MIT License.

Uses the [ff3](https://github.com/mysto/python-fpe) python package by
[mysto](https://github.com/mysto) as a reference implementation, under the Apache
2.0 License.