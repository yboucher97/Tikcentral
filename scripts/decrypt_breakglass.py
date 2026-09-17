#!/usr/bin/env python3
"""Decrypt a Tikcentral .tcbundle break-glass recovery archive."""

import getpass
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"TIKCENTRAL-BREAKGLASS-V1\n"
ITERATIONS = 600_000


def main():
    if len(sys.argv) not in {2, 3}:
        raise SystemExit("Usage: decrypt_breakglass.py INPUT.tcbundle [OUTPUT.zip]")
    source = Path(sys.argv[1])
    target = Path(sys.argv[2]) if len(sys.argv) == 3 else source.with_suffix(".zip")
    payload = source.read_bytes()
    if not payload.startswith(MAGIC):
        raise SystemExit("Not a Tikcentral break-glass bundle or unsupported format")
    offset = len(MAGIC)
    salt = payload[offset:offset + 16]
    nonce = payload[offset + 16:offset + 28]
    ciphertext = payload[offset + 28:]
    if len(salt) != 16 or len(nonce) != 12 or not ciphertext:
        raise SystemExit("Break-glass bundle is truncated")
    passphrase = getpass.getpass("Break-glass passphrase: ")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    key = kdf.derive(passphrase.encode("utf-8"))
    try:
        clear = AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    except Exception:
        raise SystemExit("Decryption failed: wrong passphrase or bundle integrity check failed")
    target.write_bytes(clear)
    print(f"Recovered ZIP: {target}")


if __name__ == "__main__":
    main()
