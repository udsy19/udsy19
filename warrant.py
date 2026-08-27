#!/usr/bin/env python3
"""
Builds, signs and renders the warrant.

A warrant is a signed statement that one party may act on another's behalf.
That is the thing I build, so the profile is one: a self-issued credential,
signed twice, that anyone can check without trusting me or GitHub.

Two signatures because that is what the migration actually looks like. Ed25519
is what everything verifies today. ML-DSA-44 (FIPS 204) is what survives a
cryptographically relevant quantum computer. During the transition you carry
both and you accept a document only if both check out.

    python3 warrant.py            build warrant.json, sign it, render README.md
    python3 warrant.py --rotate   generate a fresh keypair first

The private key lands in .warrant_key and is never committed.
"""
import base64
import datetime
import hashlib
import json
import os
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)
from cryptography.hazmat.primitives import serialization
from dilithium_py.ml_dsa import ML_DSA_44

HERE = os.path.dirname(os.path.abspath(__file__))
KEYFILE = os.path.join(HERE, ".warrant_key")
COLS = 80

b64 = lambda b: base64.b64encode(b).decode()
unb64 = base64.b64decode


# ----------------------------------------------------------------- the claims

def claims():
    """The signed payload. Order matters: it is serialised canonically, so any
    reordering, any changed character, breaks both signatures."""
    return {
        "subject": "Udaya Vijay Anand",
        "issuer": "self",
        "issued": "2026-08-27",
        "location": "New York, NY",
        "reading": "MS Quantum Science and Technology, Columbia",
        "capabilities": [
            {
                "scope": "agent.memory:write",
                "name": "Erys",
                "text": "An ambient macOS agent that watches your work, "
                        "remembers what you committed to, and follows "
                        "through on it.",
                "url": "erys.app",
            },
            {
                "scope": "agent.delegation:prove",
                "name": "Warrant",
                "text": "A delegation-proof layer for AI agents, built on "
                        "post-quantum signatures. If an agent acts for you, "
                        "there should be proof you allowed it.",
                "url": "",
            },
            {
                "scope": "graph.professional:read",
                "name": "Know",
                "text": "Professional network intelligence for B2B teams, "
                        "co-founded with a friend.",
                "url": "useknow.io",
            },
        ],
        "prior": [
            ("USENIX Security", "first-author paper on adversarial attacks "
                                "against LLM-powered security tooling"),
            ("KPMG", "incident response"),
            ("DBS Bank", "vulnerability assessment"),
            ("Purdue", "cybersecurity and network engineering"),
        ],
        "open_questions": [
            "What does it mean to prove an agent was allowed to act?",
            "Which of today's signatures will still mean anything in 2040?",
            "How much can software do for you before it stops being yours?",
        ],
    }


def canonical(payload):
    """Bytes that get signed. Sorted keys, no incidental whitespace, UTF-8 —
    so that verification depends on the content and nothing else."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# --------------------------------------------------------------------- keys

def load_or_make_keys(rotate=False):
    if os.path.exists(KEYFILE) and not rotate:
        blob = json.load(open(KEYFILE))
        ed_sk = Ed25519PrivateKey.from_private_bytes(unb64(blob["ed25519_sk"]))
        return ed_sk, unb64(blob["mldsa_pk"]), unb64(blob["mldsa_sk"])

    ed_sk = Ed25519PrivateKey.generate()
    mldsa_pk, mldsa_sk = ML_DSA_44.keygen()
    json.dump({
        "note": "PRIVATE. Never commit this file.",
        "ed25519_sk": b64(ed_sk.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption())),
        "mldsa_pk": b64(mldsa_pk),
        "mldsa_sk": b64(mldsa_sk),
    }, open(KEYFILE, "w"), indent=2)
    os.chmod(KEYFILE, 0o600)
    return ed_sk, mldsa_pk, mldsa_sk


# -------------------------------------------------------------- typography

def rule(ch="─"):
    return ch * COLS


def band(title, right=""):
    """Section rule with the title set into it."""
    left = f"── {title} "
    return (left + "─" * max(0, COLS - len(left) - len(right)) + right)[:COLS]


def wrap(text, width, indent):
    out, line = [], ""
    for word in text.split():
        if len(line) + len(word) + (1 if line else 0) > width:
            out.append(" " * indent + line)
            line = word
        else:
            line = (line + " " + word) if line else word
    if line:
        out.append(" " * indent + line)
    return out


# ----------------------------------------------------------------- rendering

def render(payload, sig, transcript):
    c = payload
    L = []
    add = L.append

    add(rule("═"))
    head = "W A R R A N T"
    tail = f"self-issued · {c['issued']}"
    add(head + " " * (COLS - len(head) - len(tail)) + tail)
    add(rule("═"))
    add("")
    add("A warrant is a signed statement that one party may act on another's")
    add("behalf. That is the thing I build, so this page is one.")
    add("")
    add("Everything here is signed twice — Ed25519 for today, ML-DSA-44 for the")
    add("decade after RSA stops being a good idea. Neither signature asks you to")
    add("trust me, or GitHub. Clone this and run the verifier yourself.")
    add("")

    add(band("SUBJECT"))
    add("")
    add(f"  {c['subject'].lower()}")
    add(f"  {c['location'].lower()} · {c['reading'].lower()}")
    add("")

    add(band("CAPABILITIES"))
    add("")
    for cap in c["capabilities"]:
        head = f"  {cap['scope']:<26}{cap['name'].lower()}"
        add(head)
        for ln in wrap(cap["text"], COLS - 30, 28):
            add(ln)
        if cap["url"]:
            add(" " * 28 + cap["url"])
        add("")

    add(band("PRIOR"))
    add("")
    for org, what in c["prior"]:
        lines = wrap(what, COLS - 28, 28)
        add(f"  {org:<26}{lines[0].lstrip()}")
        for ln in lines[1:]:
            add(ln)
    add("")

    add(band("WHAT THE SIGNATURE MEANS"))
    add("")
    add("  It proves this document has not changed since I signed it, and that")
    add("  it was signed by the holder of the key below. That is all a signature")
    add("  has ever proved. It does not attest that the section above is true —")
    add("  for that you ask the institutions, not the maths.")
    add("")
    add("  Knowing exactly where that line falls is most of my work.")
    add("")

    add(band("SIGNATURE"))
    add("")
    add(f"  payload      warrant.json          sha-256  {sig['payload_sha256'][:24]}")
    add(f"  ed25519      public key                     {sig['ed25519_pk'][:24]}")
    add(f"               signature                      {sig['ed25519_sig'][:24]}")
    add(f"  ml-dsa-44    public key   sha-256           {hashlib.sha256(unb64(sig['mldsa_pk'])).hexdigest()[:24]}")
    add(f"               signature    sha-256           {hashlib.sha256(unb64(sig['mldsa_sig'])).hexdigest()[:24]}")
    add("")
    add("  Full keys and signatures are in warrant.sig.json. The ML-DSA public")
    add("  key is 1312 bytes and its signature 2420, against 32 and 64 for")
    add("  Ed25519. That size difference is the price of the next thirty years.")
    add("")
    add("  pip install cryptography dilithium-py")
    add("")
    for ln in transcript:
        add("  " + ln)
    add("")

    add(band("NOT UNDER WARRANT"))
    add("")
    add("  Some things do not need proving.")
    add("")
    add("  I photograph people. Sony A7III, mostly the 85mm. The practice is")
    add("  called Sora.                                             thesora.io")
    add("")
    add("  I was a competitive inline speed skater in India and I am slowly")
    add("  finding my way back to it in New York.")
    add("")
    add("  I keep returning to the Mahabharata, especially the Tamil retellings.")
    add("")

    add(band("OPEN"))
    add("")
    for q in c["open_questions"]:
        add(f"  — {q}")
    add("")
    add(rule("═"))

    over = [(i, len(l)) for i, l in enumerate(L) if len(l) > COLS]
    if over:
        raise SystemExit(f"lines over {COLS} cols: {over}")

    body = "\n".join(L)
    links = ('<p align="right"><sub><samp>'
             '<a href="https://erys.app">ERYS.APP</a>&ensp;·&ensp;'
             '<a href="https://useknow.io">USEKNOW.IO</a>&ensp;·&ensp;'
             '<a href="https://thesora.io">THESORA.IO</a>&ensp;·&ensp;'
             '<a href="https://www.linkedin.com/in/udsy/">LINKEDIN</a>&ensp;·&ensp;'
             '<a href="https://instagram.com/udsyx">INSTAGRAM</a>&ensp;·&ensp;'
             '<a href="mailto:udayatejas2004@gmail.com">EMAIL</a>'
             '</samp></sub></p>')
    return ("<!-- This README is a signed document. Do not edit it by hand:\n"
            "     the signatures are over warrant.json, and hand edits here\n"
            "     will simply be overwritten. Run: python3 warrant.py -->\n\n"
            "```\n" + body + "\n```\n\n" + links + "\n")


# ---------------------------------------------------------------------- main

def main():
    rotate = "--rotate" in sys.argv
    payload = claims()
    msg = canonical(payload)

    ed_sk, mldsa_pk, mldsa_sk = load_or_make_keys(rotate)
    ed_pk = ed_sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    sig = {
        "payload": "warrant.json",
        "payload_sha256": hashlib.sha256(msg).hexdigest(),
        "ed25519_pk": b64(ed_pk),
        "ed25519_sig": b64(ed_sk.sign(msg)),
        "mldsa_alg": "ML-DSA-44 (FIPS 204)",
        "mldsa_pk": b64(mldsa_pk),
        "mldsa_sig": b64(ML_DSA_44.sign(mldsa_sk, msg)),
    }

    open(os.path.join(HERE, "warrant.json"), "wb").write(msg)
    json.dump(sig, open(os.path.join(HERE, "warrant.sig.json"), "w"), indent=2)

    out = subprocess.run([sys.executable, os.path.join(HERE, "verify.py")],
                         capture_output=True, text=True, cwd=HERE)
    transcript = ["$ python3 verify.py"] + out.stdout.rstrip("\n").split("\n")

    open(os.path.join(HERE, "README.md"), "w", encoding="utf-8").write(
        render(payload, sig, transcript))
    print("wrote warrant.json, warrant.sig.json, README.md")
    print(out.stdout, end="")


if __name__ == "__main__":
    main()
