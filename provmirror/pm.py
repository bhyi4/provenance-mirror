"""
🔎 Provenance Mirror — content authenticity VERIFIER (not a detector).

Sister tool to Measurement Mirror. Same DNA, different domain:
  measure-mirror  audits "AI evaluation claims"   (is the *claim* honest?)
  provenance-mirror audits "content authenticity"  (is the *origin* proven?)

Design principles (inherited from measure-mirror — these are the whole point):
  1. VERIFIER, not detector — we never claim "this is fake" from pixels.
     We check deterministic provenance / integrity SIGNALS only.
  2. Two-sided — "no signal" means UNVERIFIED (unknown), NOT "fake".
     Refusing to brand an unsigned real photo as fake is the core value.
  3. Honest about uncertainty — the default verdict is UNVERIFIED.
  4. Sealed ledger — every verdict is chain-hashed (tamper-evident).
  5. Input-driven — only the signals actually present in the file are read.

Zero dependencies (stdlib only). Deterministic: same bytes → same verdict.
Heavy signals (full C2PA crypto verification, ML classifiers) are explicitly
marked as NOT-IMPLEMENTED stubs — this PoC proves the *frame*, not the crypto.

Signals (each returns a Signal pointing AUTHENTIC / SYNTHETIC / TAMPERED / NONE):
  ① c2pa_manifest    — Content Credentials / C2PA manifest embedded?
  ② generator_meta   — known AI-generator signature in metadata?
  ③ ai_watermark     — declared AI-watermark / training assertion?
  ④ tamper_anchor    — same bytes previously sealed under a different origin?
  ⑤ format_integrity — container structure intact? double-compression hint?

Verdict (synthesized from the signals, honesty-first priority order):
  TAMPERED          — integrity broken (strongest negative)
  SYNTHETIC         — AI-origin signal found (declared or signatured)
  CONFLICTING       — AUTHENTIC and SYNTHETIC signals both present
  AUTHENTIC-SIGNED  — provenance signature present, nothing contradicts it
  UNVERIFIED        — no usable signal — we say "unknown", never "fake"
"""
from __future__ import annotations
import hashlib, json, os, time
from dataclasses import dataclass


# ─────────────────────────────────────────────────────────────
# Result types
# ─────────────────────────────────────────────────────────────
# A signal points in one of four directions (or NONE = silent).
AUTHENTIC = "AUTHENTIC"
SYNTHETIC = "SYNTHETIC"
TAMPERED  = "TAMPERED"
NONE      = "NONE"


@dataclass
class Signal:
    probe: str
    direction: str   # AUTHENTIC / SYNTHETIC / TAMPERED / NONE
    detail: str


# Known AI-generator fingerprints that tools routinely leave in metadata.
# (Deterministic byte-scan — not ML. Absence proves nothing; presence is a signal.)
_AI_GENERATOR_MARKERS = [
    b"Stable Diffusion", b"stable-diffusion", b"Midjourney", b"DALL-E",
    b"DALL\xc2\xb7E", b"Adobe Firefly", b"Generated with AI", b"made with AI",
    b"AI-generated", b"Imagen", b"Firefly", b"NovelAI", b"Leonardo.Ai",
    b"comfyui", b"ComfyUI", b"automatic1111",
]
# C2PA / JUMBF container markers (presence = a provenance manifest is embedded).
_C2PA_MARKERS = [b"c2pa", b"jumbf", b"urn:uuid:", b"contentauth",
                 b"Content Credentials", b"cai\x00"]
# C2PA assertions that declare AI/ML origin inside an otherwise-signed manifest.
_C2PA_AI_ASSERTIONS = [b"trainedAlgorithmicMedia", b"compositeWithTrainedAlgorithmicMedia",
                       b"c2pa.ai", b"digitalSourceType"]
# Declared watermark markers (real watermarks like SynthID are private — see stub note).
_WATERMARK_MARKERS = [b"SynthID", b"synthid", b"C2PA-watermark", b"watermark:ai"]


# ─────────────────────────────────────────────────────────────
# ① C2PA / Content Credentials manifest
# ─────────────────────────────────────────────────────────────
def c2pa_manifest_check(data: bytes) -> Signal:
    """① Is a C2PA / Content Credentials manifest embedded?

    PoC scope: detects the *presence* of a manifest by byte-scan. It does NOT
    yet cryptographically verify the signature chain — that is a documented
    TODO (needs the c2pa library). Presence alone is treated as a provenance
    signal; an embedded AI-origin assertion flips it to SYNTHETIC.
    """
    has_manifest = any(m in data for m in _C2PA_MARKERS)
    if not has_manifest:
        return Signal("① c2pa-manifest", NONE, "No C2PA / Content Credentials manifest found.")
    if any(a in data for a in _C2PA_AI_ASSERTIONS):
        return Signal("① c2pa-manifest", SYNTHETIC,
                      "C2PA manifest present AND declares AI/ML origin "
                      "(trainedAlgorithmicMedia / digitalSourceType).")
    return Signal("① c2pa-manifest", AUTHENTIC,
                  "C2PA / Content Credentials manifest present. "
                  "[PoC: signature-chain crypto NOT yet verified]")


# ─────────────────────────────────────────────────────────────
# ② Generator metadata fingerprint
# ─────────────────────────────────────────────────────────────
def generator_meta_check(data: bytes) -> Signal:
    """② Does the file carry a known AI-generator signature in its metadata?

    Many AI tools stamp their name into EXIF/XMP/PNG-text. Deterministic scan.
    Presence = SYNTHETIC signal; absence proves nothing (returns NONE).
    """
    hits = [m.decode("utf-8", "replace") for m in _AI_GENERATOR_MARKERS if m in data]
    if hits:
        return Signal("② generator-meta", SYNTHETIC,
                      "AI-generator signature in metadata: " + ", ".join(sorted(set(hits))))
    return Signal("② generator-meta", NONE, "No known AI-generator signature in metadata.")


# ─────────────────────────────────────────────────────────────
# ③ AI watermark / training assertion
# ─────────────────────────────────────────────────────────────
def ai_watermark_check(data: bytes) -> Signal:
    """③ Is a declared AI watermark / training-media assertion present?

    PoC scope: detects *declared* watermark markers by byte-scan. Real
    steganographic watermarks (e.g. SynthID) are private and cannot be read
    without the vendor detector — that path is a documented NOT-IMPLEMENTED
    stub. Absence here means "couldn't check", not "no watermark".
    """
    hits = [m.decode("utf-8", "replace") for m in _WATERMARK_MARKERS if m in data]
    if hits:
        return Signal("③ ai-watermark", SYNTHETIC,
                      "Declared AI watermark marker: " + ", ".join(sorted(set(hits))))
    return Signal("③ ai-watermark", NONE,
                  "No declared watermark marker. "
                  "[PoC: steganographic watermark detection NOT implemented]")


# ─────────────────────────────────────────────────────────────
# ④ Tamper anchor — same bytes, different declared origin
# ─────────────────────────────────────────────────────────────
def tamper_anchor_check(ledger_path: str, file_hash: str,
                        origin: str | None) -> Signal:
    """④ Has this exact content been sealed before under a *different* origin?

    Direct port of measure-mirror's anchor idea: a SHA-256 of the bytes is the
    identity. If the same hash reappears claiming a different origin, that is a
    provenance conflict (re-attribution / laundering signal) → TAMPERED.
    """
    seen_origins = _origins_for_hash(ledger_path, file_hash)
    others = [o for o in seen_origins if origin is not None and o != origin and o is not None]
    if others:
        return Signal("④ tamper-anchor", TAMPERED,
                      f"Identical bytes previously sealed under different origin(s): "
                      + ", ".join(f"'{o}'" for o in sorted(set(others))))
    return Signal("④ tamper-anchor", NONE, "No prior conflicting origin for these bytes.")


# ─────────────────────────────────────────────────────────────
# ⑤ Container format integrity
# ─────────────────────────────────────────────────────────────
def format_integrity_check(data: bytes) -> Signal:
    """⑤ Is the container structure intact? Crude double-compression hint.

    Deterministic structural checks (stdlib only):
      - magic-byte / EOI-marker sanity for JPEG and PNG
      - multiple embedded JPEG SOI markers → re-compression / splice hint
    Returns TAMPERED only on clear structural breakage; otherwise NONE
    (intact structure is not by itself a provenance signal).
    """
    if data[:3] == b"\xff\xd8\xff":  # JPEG
        if not data.rstrip(b"\x00").endswith(b"\xff\xd9"):
            return Signal("⑤ format-integrity", TAMPERED,
                          "JPEG missing EOI (0xFFD9) marker — truncated or altered.")
        soi_count = data.count(b"\xff\xd8\xff")
        if soi_count > 1:
            return Signal("⑤ format-integrity", TAMPERED,
                          f"{soi_count} embedded JPEG SOI markers — "
                          "splice / double-compression hint.")
        return Signal("⑤ format-integrity", NONE, "JPEG container structure intact.")
    if data[:8] == b"\x89PNG\r\n\x1a\n":  # PNG
        if b"IEND" not in data[-16:]:
            return Signal("⑤ format-integrity", TAMPERED,
                          "PNG missing IEND chunk near EOF — truncated or altered.")
        return Signal("⑤ format-integrity", NONE, "PNG container structure intact.")
    return Signal("⑤ format-integrity", NONE,
                  "Unrecognized container — structural check skipped.")


# ─────────────────────────────────────────────────────────────
# Verdict synthesis (honesty-first priority)
# ─────────────────────────────────────────────────────────────
def synthesize(signals: list[Signal]) -> str:
    """Collapse signals into one verdict. Order encodes the honesty policy."""
    dirs = {s.direction for s in signals}
    if TAMPERED in dirs:
        return "TAMPERED"
    if SYNTHETIC in dirs and AUTHENTIC in dirs:
        return "CONFLICTING"
    if SYNTHETIC in dirs:
        return "SYNTHETIC"
    if AUTHENTIC in dirs:
        return "AUTHENTIC-SIGNED"
    return "UNVERIFIED"   # the honest default — "unknown", never "fake"


_VERDICT_NOTE = {
    "TAMPERED":         "Integrity signal broken. Treat as altered.",
    "SYNTHETIC":        "AI-origin signal present (declared or signatured).",
    "CONFLICTING":      "Authentic and synthetic signals disagree — investigate.",
    "AUTHENTIC-SIGNED": "Provenance signature present (PoC: crypto chain not yet verified).",
    "UNVERIFIED":       "No usable signal. UNKNOWN — this is NOT evidence of fakery.",
}


# ─────────────────────────────────────────────────────────────
# Ledger (chain-hashed, ported from measure-mirror)
# ─────────────────────────────────────────────────────────────
def _get_last_seal(ledger_path: str) -> str:
    if not os.path.exists(ledger_path):
        return "GENESIS"
    last = "GENESIS"
    with open(ledger_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                last = json.loads(line).get("seal", last)
            except json.JSONDecodeError:
                continue
    return last


def _load_entries_safe(ledger_path: str) -> list[dict]:
    """Parse all valid JSON lines from the ledger (skips blanks/corrupt)."""
    if not os.path.exists(ledger_path):
        return []
    out: list[dict] = []
    with open(ledger_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _origins_for_hash(ledger_path: str, file_hash: str) -> list[str | None]:
    return [e.get("origin") for e in _load_entries_safe(ledger_path)
            if e.get("file_hash") == file_hash]


def _seal(ledger_path: str, entry: dict) -> dict:
    entry["prev_seal"] = _get_last_seal(ledger_path)
    entry["seal"] = hashlib.sha256(
        json.dumps(entry, sort_keys=True, ensure_ascii=False).encode()
    ).hexdigest()[:16]
    with open(ledger_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    return entry


# ─────────────────────────────────────────────────────────────
# verify() — the single entry point
# ─────────────────────────────────────────────────────────────
def verify(file_path: str, *, ledger_path: str = "pm_ledger.jsonl",
           origin: str | None = None, seal: bool = True) -> dict:
    """Run all signal probes on a file, synthesize a verdict, seal it.

    Args:
        file_path:   path to the content file (image, etc.)
        ledger_path: chain-hashed verdict ledger
        origin:      declared origin/source for ④ tamper-anchor (e.g. a URL or
                     uploader id). If two different origins claim identical
                     bytes, ④ fires TAMPERED.
        seal:        append the verdict to the ledger (default True)

    Returns a dict: file_hash, verdict, note, signals (list), [ledger_entry].
    Deterministic: same bytes + same ledger state → same verdict.
    """
    with open(file_path, "rb") as f:
        data = f.read()
    file_hash = hashlib.sha256(data).hexdigest()

    signals = [
        c2pa_manifest_check(data),
        generator_meta_check(data),
        ai_watermark_check(data),
        tamper_anchor_check(ledger_path, file_hash, origin),
        format_integrity_check(data),
    ]
    verdict = synthesize(signals)

    result = {
        "file_hash": file_hash,
        "origin":    origin,
        "verdict":   verdict,
        "note":      _VERDICT_NOTE[verdict],
        "signals":   [{"probe": s.probe, "direction": s.direction, "detail": s.detail}
                      for s in signals],
    }
    if seal:
        entry = _seal(ledger_path, {
            "_type":     "verdict",
            "ts":        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "file_hash": file_hash,
            "origin":    origin,
            "verdict":   verdict,
            "signals":   {s.probe[:1] or s.probe: s.direction for s in signals},
        })
        result["ledger_entry"] = entry
    return result


# ─────────────────────────────────────────────────────────────
# Certificate + badge (verdict-colored, ported from measure-mirror)
# ─────────────────────────────────────────────────────────────
_BADGE_COLOR = {
    "AUTHENTIC-SIGNED": ("brightgreen", "#4c1"),
    "UNVERIFIED":       ("lightgrey",   "#9f9f9f"),
    "SYNTHETIC":        ("orange",      "#fe7d37"),
    "CONFLICTING":      ("yellow",      "#dfb317"),
    "TAMPERED":         ("red",         "#e05d44"),
}


def badge(result: dict, *, fmt: str = "markdown") -> str:
    """🏷 Render a verify() result as an embeddable badge (markdown / svg)."""
    verdict = result["verdict"]
    color_name, color_hex = _BADGE_COLOR[verdict]
    short = result["file_hash"][:12]
    if fmt == "markdown":
        v = verdict.replace("-", "--")
        return (f"![🔎 {short}: {verdict}]"
                f"(https://img.shields.io/badge/🔎_{short}-{v}-{color_name})")
    if fmt == "svg":
        label = f"🔎 {short}"
        lw, vw = len(label) * 7 + 16, len(verdict) * 7 + 16
        return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{lw+vw}" height="20">'
                f'<title>{label}: {verdict}</title>'
                f'<rect width="{lw}" height="20" fill="#555"/>'
                f'<rect x="{lw}" width="{vw}" height="20" fill="{color_hex}"/>'
                f'<g fill="#fff" font-family="Verdana,sans-serif" font-size="11" text-anchor="middle">'
                f'<text x="{lw//2}" y="14">{label}</text>'
                f'<text x="{lw+vw//2}" y="14">{verdict}</text></g></svg>')
    raise ValueError(f"Unknown badge format: {fmt!r}")


# ─────────────────────────────────────────────────────────────
# Report printer
# ─────────────────────────────────────────────────────────────
_ICON = {AUTHENTIC: "🟢", SYNTHETIC: "🟠", TAMPERED: "🔴", NONE: "⚪"}
_VERDICT_ICON = {"AUTHENTIC-SIGNED": "🟢", "UNVERIFIED": "⚪",
                 "SYNTHETIC": "🟠", "CONFLICTING": "🟡", "TAMPERED": "🔴"}


def report(result: dict) -> None:
    print(f"\n🔎 Provenance: {result['file_hash'][:16]}…")
    print(f"   Verdict: {_VERDICT_ICON[result['verdict']]} {result['verdict']}")
    print(f"   {result['note']}")
    for s in result["signals"]:
        print(f"   {_ICON[s['direction']]} [{s['probe']}] {s['detail']}")


# ─────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────
def _cli() -> None:
    import argparse, sys
    p = argparse.ArgumentParser(
        prog="pm", description="🔎 Provenance Mirror — content authenticity verifier")
    p.add_argument("--ledger", default=os.environ.get("PM_LEDGER", "pm_ledger.jsonl"),
                   help="Ledger path (default: $PM_LEDGER or ./pm_ledger.jsonl)")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("verify", help="Verify a content file's provenance/integrity")
    v.add_argument("file")
    v.add_argument("--origin", default=None, help="Declared origin/source (enables ④ tamper-anchor)")
    v.add_argument("--badge", choices=["markdown", "svg"], default=None)
    v.add_argument("--no-seal", action="store_true", help="Do not write to the ledger")

    d = sub.add_parser("distribute",
                       help="Fingerprint a text file for a recipient + seal the distribution")
    d.add_argument("file", help="Text file to distribute")
    d.add_argument("--to", required=True, help="Recipient id")
    d.add_argument("--doc-id", required=True, help="Document identifier")
    d.add_argument("--out", default=None, help="Write the fingerprinted copy here (default: stdout)")

    t = sub.add_parser("trace", help="Trace a leaked text file back to a recipient")
    t.add_argument("file", help="Leaked/surfaced text file")

    args = p.parse_args()
    if args.cmd == "verify":
        if not os.path.exists(args.file):
            p.error(f"file not found: {args.file}")
        res = verify(args.file, ledger_path=args.ledger,
                     origin=args.origin, seal=not args.no_seal)
        if args.badge:
            print(badge(res, fmt=args.badge))
        else:
            report(res)
    elif args.cmd == "distribute":
        from . import tracing
        with open(args.file, encoding="utf-8") as f:
            text = f.read()
        out = tracing.distribute(text, recipient=args.to, doc_id=args.doc_id,
                                 ledger_path=args.ledger)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(out["marked_text"])
            print(f"🔏 Distributed '{args.doc_id}' → {args.to}  "
                  f"marked_hash={out['marked_hash']}  → {args.out}")
        else:
            sys.stdout.write(out["marked_text"])
    elif args.cmd == "trace":
        from . import tracing
        with open(args.file, encoding="utf-8") as f:
            text = f.read()
        res = tracing.trace(text, ledger_path=args.ledger)
        icon = {"CONFIRMED": "🎯", "FINGERPRINT-ONLY": "🔬", "HASH-MATCH": "🧬",
                "DOC-KNOWN": "📄", "UNTRACEABLE": "⚪"}
        print(f"{icon.get(res['verdict'], '•')} {res['verdict']}"
              + (f" → recipient='{res['recipient']}'" if res.get('recipient') else "")
              + (f"  doc='{res['doc_id']}'" if res.get('doc_id') else ""))
        print(f"   {res['note']}")


if __name__ == "__main__":
    _cli()
