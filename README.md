# fastfpe

Fast Format Preserving Encryption (FPE) implementation in Rust with Python
bindings.

Format-preserving encryption (FPE) is a cryptographic method that encrypts data
while preserving its format. For example, encrypting a credit card number yields
another valid-looking credit card number, making it useful for data protection
while maintaining compatibility with existing systems.


## Features

- FF3-1 Format Preserving Encryption algorithm
- Fast Rust implementation with Python bindings
- Support for custom alphabets
- Thread-safe

## Installation

```bash
pip install fastfpe
```

## Usage

```python
>>> from fastfpe import ff3_1
>>> 
>>> key = "3eaa133d22a7ee2432fb8ecfde1e97d9106dcf26b9edaa52b3ed4acd9a9b8445"
>>> tweak = "5be49f26c1dbb7"  # 7 bytes, hex-encoded
>>> alphabet = "abcdef0123456789"
>>> plaintext = "024587931578"
>>> 
>>> # Encrypt
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

## License

Licensed under the MIT License. See [LICENSE](LICENSE) for more information.

Uses the [rust-fpe](https://github.com/johntyner/rust-fpe) implementation by
[johntyner](https://github.com/johntyner), under the MIT License.

Uses the [ff3](https://github.com/mysto/python-fpe) python package by
[mysto](https://github.com/mysto) as a reference implementation, under the Apache
2.0 License.