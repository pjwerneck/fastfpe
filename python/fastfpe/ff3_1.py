"""FF3-1 (Format-Preserving Encryption) helpers.

Functions:
- encrypt(key, tweak, alphabet, plaintext) -> ciphertext
- decrypt(key, tweak, alphabet, ciphertext) -> plaintext

Notes:
- Keys are hex-encoded AES keys (16/24/32 bytes).
- Tweak for FF3-1 MUST be exactly 7 bytes (14 hex chars) after decoding.
- Alphabet defines the valid characters and sets radix; inputs must use only these chars.
- FF3-1 retained for compatibility; FF1 recommended for new deployments.
"""

from ._rust_fastfpe import ff3_1_decrypt as decrypt
from ._rust_fastfpe import ff3_1_encrypt as encrypt

__all__ = ["encrypt", "decrypt"]
