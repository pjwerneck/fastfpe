"""FF1 (Format-Preserving Encryption) helpers.

This module exposes two functions:

- encrypt(key, tweak, alphabet, plaintext) -> ciphertext
- decrypt(key, tweak, alphabet, ciphertext) -> plaintext

Notes:
- Keys are hex-encoded AES keys of 16/24/32 bytes (128/192/256-bit).
- Tweak is hex-encoded and may be empty or variable length (FF1).
- Alphabet defines the valid characters and sets the radix; inputs must use only these chars.
"""

from ._rust_fastfpe import ff1_decrypt as decrypt
from ._rust_fastfpe import ff1_encrypt as encrypt

__all__ = ["encrypt", "decrypt"]
