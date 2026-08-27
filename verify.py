#!/usr/bin/env python3
"""
Checks the warrant.

    pip install cryptography dilithium-py
    python3 verify.py

Reads warrant.json and warrant.sig.json, checks both signatures over the
payload bytes, and exits non-zero if either fails. No network, nothing to
trust but the files in front of you.

Change one character of warrant.json and both checks fail. That is the
entire point of the document.
"""
import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
unb64 = base64.b64decode


def main():
    payload = open(os.path.join(HERE, "warrant.json"), "rb").read()
    sig = json.load(open(os.path.join(HERE, "warrant.sig.json")))

    ok = True
    digest = hashlib.sha256(payload).hexdigest()
    if digest != sig["payload_sha256"]:
        print(f"[fail] sha-256     payload digest does not match the record")
        ok = False
    else:
        print(f"[ ok ] sha-256     {digest[:24]}")

    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(unb64(sig["ed25519_pk"])).verify(
            unb64(sig["ed25519_sig"]), payload)
        print(f"[ ok ] ed25519     signature valid")
    except Exception:
        print(f"[fail] ed25519     signature INVALID")
        ok = False

    try:
        from dilithium_py.ml_dsa import ML_DSA_44
        good = ML_DSA_44.verify(unb64(sig["mldsa_pk"]),
                                payload, unb64(sig["mldsa_sig"]))
        print(f"[{' ok ' if good else 'fail'}] ml-dsa-44   "
              f"signature {'valid' if good else 'INVALID'}   FIPS 204")
        ok &= good
    except ImportError:
        print("[skip] ml-dsa-44   dilithium-py not installed")

    print("warrant intact." if ok else "warrant BROKEN.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
