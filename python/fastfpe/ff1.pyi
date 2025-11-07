from typing import Final

def encrypt(key: str, tweak: str, alphabet: str, plaintext: str) -> str:
    """Encrypt plaintext using FF1 format-preserving encryption.

    Args:
            key (str): Hex-encoded AES key (16, 24, or 32 bytes after decoding).
            tweak (str): Hex-encoded tweak; may be empty or variable length (subject to NIST SP 800-38G limits).
            alphabet (str): Set of valid characters; its length is the radix.
            plaintext (str): Input text composed only of characters from alphabet.

    Returns:
            str: Ciphertext using the same alphabet.

    Raises:
            ValueError: On invalid key, tweak, alphabet, or length constraints.
    """
    ...

def decrypt(key: str, tweak: str, alphabet: str, ciphertext: str) -> str:
    """Decrypt ciphertext using FF1 format-preserving encryption.

    Args:
            key (str): Hex-encoded AES key (16, 24, or 32 bytes after decoding).
            tweak (str): Hex-encoded tweak; may be empty or variable length.
            alphabet (str): Set of valid characters; its length is the radix.
            ciphertext (str): Encrypted text composed only of characters from alphabet.

    Returns:
            str: Decrypted plaintext.

    Raises:
            ValueError: On invalid key, tweak, alphabet, or length constraints.
    """
    ...

__all__: Final = ["encrypt", "decrypt"]
