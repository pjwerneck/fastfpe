def encrypt(key: str, tweak: str, alphabet: str, plaintext: str) -> str:
    """Encrypts plaintext using FF3-1 format-preserving encryption

    Args:
        key (str): Hex-encoded AES key (16, 24, or 32 bytes after decoding)
        tweak (str): Hex-encoded tweak (7 or 8 bytes after decoding)
        alphabet (str): String containing the valid characters
        plaintext (str): Text to encrypt, must contain only characters from alphabet

    Returns:
        str: The encrypted text

    Raises:
        ValueError: If inputs are invalid
    """
    ...

def decrypt(key: str, tweak: str, alphabet: str, ciphertext: str) -> str:
    """Decrypts ciphertext using FF3-1 format-preserving encryption

    Args:
        key (str): Hex-encoded AES key (16, 24, or 32 bytes after decoding)
        tweak (str): Hex-encoded tweak (7 or 8 bytes after decoding)
        alphabet (str): String containing the valid characters
        ciphertext (str): Text to decrypt, must contain only characters from alphabet

    Returns:
        str: The decrypted text

    Raises:
        ValueError: If inputs are invalid
    """
    ...
