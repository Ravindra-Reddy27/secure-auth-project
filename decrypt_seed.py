#!/usr/bin/env python3
import base64
import pathlib
import os
import sys
from typing import Any, Optional

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

# Paths / constants
PRIVATE_KEY_PATH = "student_private.pem"         # adjust if your key is elsewhere
OUTPUT_SEED_PATH = "/data/seed.txt"              # default per spec; change for local testing
ENCRYPTED_INPUT = "encrypted_seed.txt"           # input file created from instructor API


def load_private_key(pem_path: str, password: Optional[bytes] = None) -> Any:
    p = pathlib.Path(pem_path)
    if not p.exists():
        raise FileNotFoundError(f"Private key not found at: {pem_path}")
    data = p.read_bytes()
    # If your private key is encrypted, provide password bytes (e.g. b"mypassword")
    private_key = load_pem_private_key(data, password=password)
    return private_key


def decrypt_seed(encrypted_seed_b64: str, private_key: Any) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP (SHA-256).
    Returns the decrypted hex seed as lowercase 64-character string.
    Raises ValueError on invalid format or decryption errors.
    """
    # 1. Base64 decode (strip whitespace/newlines first)
    try:
        b64 = encrypted_seed_b64.strip()
        ciphertext = base64.b64decode(b64, validate=True)
    except Exception as e:
        raise ValueError(f"Invalid base64 encrypted seed: {e}")

    # 2. RSA/OAEP decrypt with SHA-256 and MGF1(SHA-256)
    try:
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        # Keep error informative but avoid leaking sensitive internal data
        raise ValueError("RSA decryption failed (ciphertext may be corrupt or wrong key).")

    # 3. Decode bytes to UTF-8 string
    try:
        plaintext = plaintext_bytes.decode("utf-8")
    except Exception as e:
        raise ValueError("Decrypted data is not valid UTF-8.")

    # Trim whitespace (if any)
    plaintext = plaintext.strip()

    # 4. Validate: must be 64-character hex string
    seed = plaintext.lower()
    if len(seed) != 64:
        raise ValueError(f"Decrypted seed length != 64 (got {len(seed)}).")
    if not all(c in "0123456789abcdef" for c in seed):
        raise ValueError("Decrypted seed contains non-hex characters.")

    # 5. Return hex seed
    return seed


def save_seed_to_file(hex_seed: str, path: str = OUTPUT_SEED_PATH):
    p = pathlib.Path(path)
    # Ensure parent directory exists
    p.parent.mkdir(parents=True, exist_ok=True)
    # Write seed (no newline required, but if you want newline add + "\n")
    p.write_text(hex_seed, encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except Exception:
        # Not critical on some platforms (Windows). Ignore failure.
        pass


if __name__ == "__main__":
    try:
        enc_file = pathlib.Path(ENCRYPTED_INPUT)
        if not enc_file.exists():
            print(f"{ENCRYPTED_INPUT} not found in current directory.", file=sys.stderr)
            sys.exit(1)

        encrypted_seed_b64 = enc_file.read_text(encoding="utf-8").strip()
        priv = load_private_key(PRIVATE_KEY_PATH, password=None)  # if key is encrypted, pass password as bytes
        seed_hex = decrypt_seed(encrypted_seed_b64, priv)

        # Save to /data/seed.txt by default (or overridden)
        save_seed_to_file(seed_hex, OUTPUT_SEED_PATH)
        print(f"Decrypted seed saved to {OUTPUT_SEED_PATH}:")
        print(seed_hex)

    except Exception as e:
        print("ERROR:", e, file=sys.stderr)
        sys.exit(1)
