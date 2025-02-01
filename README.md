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


## License

fastfpe is licensed under the MIT License. See [LICENSE](LICENSE) for more information.

fastfpe uses the [rust-fpe](https://github.com/johntyner/rust-fpe) library by
[johntyner](https://github.com/johntyner) under the MIT License.


