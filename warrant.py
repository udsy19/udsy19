#!/usr/bin/env python3
"""
Builds, signs and renders the sheet.

The profile is one sheet of the same document as udsy.in: a label gutter,
hairlines, registration marks. It is also a signed document, self-issued,
so anyone can check it has not changed without trusting me or GitHub.

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
            ["open source", "82 PRs merged · 5,359 contributions / yr"],
            ["status", "open to summer '27 internships"],
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

GUTTER = 14                       # label column, like the site's gutter
BODY = COLS - GUTTER - 3          # content column after " │ "
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


class Sheet:
    """Lines of a sheet: a label gutter on the left, a rule between bands,
    and a registration mark where rule and gutter line cross."""

    def __init__(self):
        self.L = []

    def rule(self, join="┼"):
        self.L.append("─" * GUTTER + join + "─" * (COLS - GUTTER - 1))

    def row(self, label, text=""):
        self.L.append(f"{label:<{GUTTER}}│ {text}"[:COLS].rstrip())

    def band(self, label, lines, count=None):
        """A band: label (and count) in the gutter beside the first lines,
        empty gutter beside the rest."""
        tag = label if count is None else f"{label:<10}{count:02d}"
        for i, text in enumerate(lines):
            self.row(tag if i == 0 else "", text)

    def blank(self):
        self.row("")


def render(payload, sig, transcript):
    c = payload
    s = Sheet()

    left = "udsy"
    mid = "work · projects · open source"
    right = c["site"]
    gap = COLS - len(left) - len(mid) - len(right)
    s.L.append(left + " " * (gap // 2) + mid + " " * (gap - gap // 2) + right)
    s.rule("┬")

    # unit
    s.row("unit", c["subject"])
    for k, v in c["unit"]:
        s.row(k, v)
    s.rule()

    # bio
    lines = []
    for i, para in enumerate(c["bio"]):
        if i:
            lines.append("")
        lines += wrap(para, BODY)
    s.band("bio", lines)
    s.rule()

    # selected: name and state on one line, the clause beneath
    lines = []
    for name, clause, state in c["selected"]:
        mark = f"{STATUS[state]} {state}"
        lines.append(f"{name:<{BODY - len(mark)}}{mark}")
        lines += ["  " + l for l in wrap(clause, BODY - 2)]
    s.band("selected", lines, len(c["selected"]))
    s.rule()

    lines = []
    for name, clause, year in c["more"]:
        lines.append(f"{name:<{BODY - len(year)}}{year}")
        lines += ["  " + l for l in wrap(clause, BODY - 2)]
    s.band("more", lines, len(c["more"]))
    s.rule()

    for label, key in (("work", "work"), ("education", "education")):
        lines = []
        for i, (year, title, detail) in enumerate(c[key]):
            if i:
                lines.append("")
            lines.append(f"{year:<9}{title}")
            lines += [" " * 9 + l for l in wrap(detail, BODY - 9)]
        s.band(label, lines, len(c[key]))
        s.rule()

    s.band("contact", [f"{k:<10}{v}" for k, v, _ in c["contact"]])
    s.rule()

    # signature: what it proves, and how to check it
    lines = wrap(
        "this sheet is signed twice: ed25519 for today, ml-dsa-44 (FIPS 204) "
        "for the decade after RSA stops being a good idea. the signature proves "
        "the sheet has not changed since it was signed, and nothing more.", BODY) + [
        "",
        f"payload    warrant.json   sha-256   {sig['payload_sha256'][:24]}",
        f"ed25519    public key               {sig['ed25519_pk'][:24]}",
        f"           signature                {sig['ed25519_sig'][:24]}",
        f"ml-dsa-44  public key     sha-256   {hashlib.sha256(unb64(sig['mldsa_pk'])).hexdigest()[:24]}",
        f"           signature      sha-256   {hashlib.sha256(unb64(sig['mldsa_sig'])).hexdigest()[:24]}",
        "",
        "pip install cryptography dilithium-py",
    ] + transcript
    s.band("signature", lines)
    s.rule("┴")
    s.L.append(f"sheet 01 / 01 · issued {c['issued']} · {c['site']}")

    body = "\n".join(s.L)
    header = (
        '<picture>\n'
        '  <source media="(prefers-color-scheme: dark)" srcset="assets/sheet-dark.png">\n'
        '  <img alt="udaya vijay anand — security engineer, agentic systems" src="assets/sheet-light.png" width="100%">\n'
        '</picture>\n\n')
    links = ("<p align=\"right\"><sub><samp>" + "&ensp;·&ensp;".join(
        f'<a href="{href}">{k}</a>' for k, _, href in c["contact"]) +
        f'&ensp;·&ensp;<a href="https://{c["site"]}">{c["site"]}</a></samp></sub></p>')
    return ("<!-- This README is a signed document. Do not edit it by hand:\n"
            "     the signatures are over warrant.json, and hand edits here\n"
            "     will simply be overwritten. Run: python3 warrant.py -->\n\n"
            + header + "```\n" + body + "\n```\n\n" + links + "\n")


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
