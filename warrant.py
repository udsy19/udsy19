#!/usr/bin/env python3
"""
Builds, signs and renders the sheet.

The profile is the same paper as udsy.in, drawn in plain text: a centred
title block, a contents list with leaders, an abstract between rules, then
sections with counts. It is also a signed document, self-issued, so anyone
can check it has not changed without trusting me or GitHub.

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


# ------------------------------------------------------------------ the sheet

def claims():
    """The signed payload: everything on the sheet. It is serialised
    canonically, so any reordering or changed character breaks both
    signatures."""
    return {
        "subject": "udaya vijay anand",
        "issuer": "self",
        "issued": datetime.date.today().isoformat(),
        "site": "udsy.in",
        "unit": [
            ["role", "security engineer · agentic systems"],
            ["base", "new york city"],
            ["school", "columbia MS '27 · purdue BS '26"],
            ["open source", "92 PRs merged · 5,654 contributions / yr"],
            ["status", "open to summer '27 internships"],
        ],
        "contents": [
            ["work", "8 roles · 3 schools"],
            ["projects", "15 entries"],
            ["open source", "live on udsy.in/oss"],
            ["blog", "2 field notes"],
        ],
        "bio": [
            "i build and break agentic systems: infra, pipelines, evals, "
            "automated red teaming, and getting them to work in production. "
            "purdue '26 → columbia MS, where i do research on browser-agent speed.",
            "co-founded know · 4x hackathon winner · photography @ sora.",
        ],
        "selected": [
            ["phantom", "autonomous black-box pentest platform", "shipped"],
            ["quipuu", "post-quantum crypto scanner in rust", "active"],
            ["indexone", "tamper-evident chain of authority for multi-agent actions", "archived"],
            ["soc adversarial eval", "attacking LLM security monitors", "under review"],
            ["erys", "ambient macOS agent", "shelved"],
            ["dsource", "browser-based space-planning editor", "active"],
        ],
        "more": [
            ["simulation-labs", "finalist @ H company computer-use hackathon", "'26"],
            ["spotlight", "investor agent that cites a source span for every claim. hack nation", "'26"],
            ["tablestakes", "where to eat right now, with receipts. claude impact lab hackathon", "'26"],
            ["muse", "always-on voice agent for macOS", "'26"],
            ["successor", "tacit-knowledge capture with a cite-or-refuse desk", "'26"],
            ["resume-builder", "one-page LaTeX resumes, fit measured by compiling the PDF", "'26"],
            ["fx3.io", "ai podcast generator with voice cloning. next.js + python, deployed on railway", "'26"],
        ],
        "work": [
            ["'26–", "research assistant · columbia", "ai agents: browser-use latency + speed optimisation."],
            ["'25–'26", "co-founder & CTO · know", "B2B network intelligence. a team's linkedin networks as one searchable graph: semantic search, warm-intro paths, multi-tenant RLS. with @satyam. closed may '26."],
            ["'25", "campus strategist · perplexity", "drove Comet sign-ups via campaigns, demos, workshops."],
            ["'25", "cyber defence & IR · KPMG india", "IR triage + malware analysis. SIEM detections mapped to MITRE ATT&CK (+30% coverage). AI safety guardrails middleware across 5 LLM providers, 25–40 TPS at sub-500ms P95."],
            ["'24", "vulnerability assessment · DBS bank", "led Rapid7 InsightVM POC for RBI compliance (+25% detection speed). async crawler over 70k+ NCIIPC advisory pages at 99%+ completeness."],
            ["'24–'25", "TA · purdue", "CNIT 176 + 271 (IT architecture, cybersecurity fundamentals). designed 22 hands-on labs on TCP/IP, linux admin, hardening for 75 students (+15% scores)."],
            ["'23", "ML research · ASSISTments (WPI)", "auto-grader at 79% accuracy, supported $8M DoE grant."],
            ["'20–'21", "project + supervising intern · unilever", "4M (man, machine, material, method) process optimization, AI workflow tracking, contractor ops."],
        ],
        "education": [
            ["'26–'27", "columbia · MS quantum science & technology", "expected dec '27."],
            ["'23–'26", "purdue · BS cybersecurity & network engineering", "finance minor · 3.6 GPA · security+, cysa+, csap, ceh"],
            ["'22–'23", "WPI · BS computer science", "3.8 GPA · dean's list. transferred."],
        ],
        "contact": [
            ["email", "udaya.vijayanand@gmail.com", "mailto:udaya.vijayanand@gmail.com"],
            ["github", "github.com/udsy19", "https://github.com/udsy19"],
            ["linkedin", "linkedin.com/in/udsy", "https://www.linkedin.com/in/udsy"],
            ["sora", "thesora.io", "https://thesora.io"],
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

BODY = 64                         # the reading measure, centred in 80 columns
STATUS = {"shipped": "■", "active": "▣", "under review": "◫",
          "shelved": "□", "archived": "□"}


def wrap(text, width):
    out, line = [], ""
    for word in text.split():
        if len(line) + len(word) + (1 if line else 0) > width:
            out.append(line)
            line = word
        else:
            line = (line + " " + word) if line else word
    if line:
        out.append(line)
    return out


class Paper:
    """Lines of the paper: everything is centred in 80 columns, sections
    have a heading with a count, and a rule is a run of ─ across the
    reading measure."""

    def __init__(self):
        self.L = []

    def pad(self, text=""):
        left = (COLS - BODY) // 2
        self.L.append((" " * left + text).rstrip())

    def centre(self, text):
        self.L.append(text.center(COLS).rstrip())

    def rule(self):
        self.pad("─" * BODY)

    def blank(self):
        self.L.append("")

    def lead(self, text):
        self.pad(text.upper())

    def heading(self, title, count=None):
        self.blank()
        self.pad(title if count is None else f"{title}  {count:02d}")
        self.blank()

    def body(self, lines):
        for l in lines:
            self.pad(l)

    def spread(self, left, right):
        """left text, right text, the space between filled."""
        gap = BODY - len(left) - len(right)
        self.pad(left + " " * max(1, gap) + right)


def render(payload, sig, transcript):
    c = payload
    s = Paper()
    unit = dict(c["unit"])

    # topline, title block
    s.spread("udsy", unit["base"].upper())
    s.blank()
    s.centre(c["subject"])
    s.centre(unit["role"])
    s.centre(unit["school"].upper())
    s.centre(unit["status"].upper())
    s.blank()

    # contents, with leaders
    s.lead("contents")
    for i, (title, note) in enumerate(c["contents"], 1):
        head = f"{i}  {title} "
        s.pad(head + "·" * (BODY - len(head) - len(note) - 1) + " " + note)
    s.blank()

    # abstract: the bio
    s.rule()
    s.lead("bio")
    for i, para in enumerate(c["bio"]):
        if i:
            s.blank()
        s.body(wrap(para, BODY))
    s.blank()
    s.pad(f"open source · {unit['open source']}")
    s.rule()

    # selected: name and state on one line, the clause beneath
    s.heading("selected", len(c["selected"]))
    for name, clause, state in c["selected"]:
        s.spread(name, f"{STATUS[state]} {state}")
        s.body(["  " + l for l in wrap(clause, BODY - 2)])

    s.heading("more", len(c["more"]))
    for name, clause, year in c["more"]:
        s.spread(name, year)
        s.body(["  " + l for l in wrap(clause, BODY - 2)])

    for label, key in (("work", "work"), ("education", "education")):
        s.heading(label, len(c[key]))
        for i, (year, title, detail) in enumerate(c[key]):
            if i:
                s.blank()
            s.spread(title, year)
            s.body(["  " + l for l in wrap(detail, BODY - 2)])

    # foot
    s.blank()
    s.rule()
    vals = [v for _, v, _ in c["contact"]]
    s.pad("   ".join(vals[:2]))
    s.pad("   ".join(vals[2:]))
    s.pad(f"© {c['issued'][:4]} {c['subject']}")

    # signature: what it proves, and how to check it
    s.heading("signature")
    s.body(wrap(
        "this paper is signed twice: ed25519 for today, ml-dsa-44 (FIPS 204) "
        "for the decade after RSA stops being a good idea. the signature proves "
        "the paper has not changed since it was signed, and nothing more.", BODY))
    s.blank()
    s.body([
        f"payload    warrant.json   sha-256   {sig['payload_sha256'][:24]}",
        f"ed25519    public key               {sig['ed25519_pk'][:24]}",
        f"           signature                {sig['ed25519_sig'][:24]}",
        f"ml-dsa-44  public key     sha-256   {hashlib.sha256(unb64(sig['mldsa_pk'])).hexdigest()[:24]}",
        f"           signature      sha-256   {hashlib.sha256(unb64(sig['mldsa_sig'])).hexdigest()[:24]}",
        "",
        f"issued     {c['issued']}",
        "",
        "pip install cryptography dilithium-py",
    ] + transcript)
    s.blank()
    s.rule()

    body = "\n".join(s.L)
    # no header image: the owner removed it, the sheet is the text
    links = ("<p align=\"right\"><sub><samp>" + "&ensp;·&ensp;".join(
        f'<a href="{href}">{k}</a>' for k, _, href in c["contact"]) +
        f'&ensp;·&ensp;<a href="https://{c["site"]}">{c["site"]}</a></samp></sub></p>')
    return ("<!-- This README is a signed document. Do not edit it by hand:\n"
            "     the signatures are over warrant.json, and hand edits here\n"
            "     will simply be overwritten. Run: python3 warrant.py -->\n\n"
            + "```\n" + body + "\n```\n\n" + links + "\n")


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
