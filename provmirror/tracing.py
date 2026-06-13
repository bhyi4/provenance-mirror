"""
🔬 Provenance Mirror — traitor tracing (leak attribution) for text/documents.

We cannot stop a leak (preventing read = DRM = not our game). We CAN prove a
leak happened and trace WHICH recipient's copy leaked. This is the verifier
philosophy applied to distribution: "who leaked it", provably, not "lock it".

Two mechanisms, sealed into the same ledger as pm.verify():

A. FINGERPRINT — each recipient gets a perceptually-identical copy carrying an
   invisible per-recipient mark. When a leaked copy surfaces, decode the mark
   → the recipient ID. (Defeats plain copy/paste; see honest limits below.)

B. DISTRIBUTION LEDGER — every distribute() is chain-sealed: "these bytes /
   this fingerprint went to recipient R at time T". trace() reads a surfaced
   copy and answers WHO, cross-checked against the sealed distribution record.

Text fingerprinting (zero-dependency, deterministic):
  Zero-width characters encode a recipient bit-string, hidden between words.
    U+200B (ZERO WIDTH SPACE)        = bit 0
    U+200C (ZERO WIDTH NON-JOINER)   = bit 1
    U+200D (ZERO WIDTH JOINER)       = framing marker (start/end sentinel)
  Invisible in every normal renderer; survives copy/paste of the text; the
  recipient id is recovered by decoding the bit-string between sentinels.

Honest limitations (read before trusting):
  - Survives copy/paste and most rich-text round-trips. Does NOT survive
    re-typing, OCR, screenshotting, or a strip step that removes zero-width
    chars (a knowledgeable leaker can launder it). This raises the cost of
    leaking cleanly; it is not unbreakable.
  - Attribution proves which *copy* leaked, not who physically leaked it
    (a recipient can be framed if their copy is stolen). Treat as evidence,
    not verdict.
  - Marks are visible to anyone who looks for zero-width bytes. Obfuscation,
    not encryption.
"""
from __future__ import annotations
import hashlib, json, os, time

from . import pm


# Zero-width codepoints
_Z0 = "​"   # bit 0
_Z1 = "‌"   # bit 1
_ZS = "‍"   # sentinel / frame
_ZW_ALL = (_Z0, _Z1, _ZS)


# ─────────────────────────────────────────────────────────────
# Bit <-> zero-width codec
# ─────────────────────────────────────────────────────────────
def _id_to_bits(recipient: str) -> str:
    """Recipient id → bit-string (UTF-8 bytes, 8 bits each)."""
    return "".join(f"{b:08b}" for b in recipient.encode("utf-8"))


def _bits_to_id(bits: str) -> str | None:
    """Bit-string → recipient id (None if not a whole number of valid bytes)."""
    if not bits or len(bits) % 8 != 0:
        return None
    try:
        data = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
        return data.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def _encode_mark(recipient: str) -> str:
    """recipient → invisible zero-width payload, sentinel-framed."""
    bits = _id_to_bits(recipient)
    body = "".join(_Z1 if b == "1" else _Z0 for b in bits)
    return _ZS + body + _ZS


def _strip_marks(text: str) -> str:
    """Remove all zero-width marker chars (normalize before re-marking)."""
    return "".join(ch for ch in text if ch not in _ZW_ALL)


def _extract_payload(text: str) -> str | None:
    """Pull the bit-string between the first sentinel pair, if any."""
    start = text.find(_ZS)
    if start == -1:
        return None
    end = text.find(_ZS, start + 1)
    if end == -1:
        return None
    body = text[start + 1:end]
    bits = "".join("1" if ch == _Z1 else "0" for ch in body if ch in (_Z0, _Z1))
    return bits or None


# ─────────────────────────────────────────────────────────────
# A. Fingerprint a text copy for a recipient
# ─────────────────────────────────────────────────────────────
def fingerprint_text(text: str, recipient: str) -> str:
    """Return a perceptually-identical copy carrying recipient's invisible mark.

    The mark is inserted after the first whitespace (so it sits between words,
    invisible). Any pre-existing marks are stripped first so re-distribution to
    a new recipient overwrites cleanly.
    """
    clean = _strip_marks(text)
    mark = _encode_mark(recipient)
    # insert at the first space; fall back to prepending
    idx = clean.find(" ")
    if idx == -1:
        return mark + clean
    return clean[:idx + 1] + mark + clean[idx + 1:]


def read_fingerprint(text: str) -> str | None:
    """Decode the recipient id embedded in a (possibly leaked) text copy."""
    bits = _extract_payload(text)
    if bits is None:
        return None
    return _bits_to_id(bits)


# ─────────────────────────────────────────────────────────────
# B. Distribution ledger + trace
# ─────────────────────────────────────────────────────────────
def distribute(text: str, *, recipient: str, doc_id: str,
               ledger_path: str = "pm_ledger.jsonl") -> dict:
    """Fingerprint `text` for `recipient` and seal the distribution record.

    Returns {recipient, doc_id, marked_text, clean_hash, marked_hash,
             ledger_entry}. clean_hash identifies the underlying document
            (mark-independent); marked_hash identifies this exact copy.
    """
    marked = fingerprint_text(text, recipient)
    clean_hash  = hashlib.sha256(_strip_marks(text).encode("utf-8")).hexdigest()[:16]
    marked_hash = hashlib.sha256(marked.encode("utf-8")).hexdigest()[:16]

    entry = pm._seal(ledger_path, {
        "_type":       "distribution",
        "ts":          time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "doc_id":      doc_id,
        "recipient":   recipient,
        "clean_hash":  clean_hash,
        "marked_hash": marked_hash,
    })
    return {
        "recipient":   recipient,
        "doc_id":      doc_id,
        "marked_text": marked,
        "clean_hash":  clean_hash,
        "marked_hash": marked_hash,
        "ledger_entry": entry,
    }


def trace(leaked_text: str, *, ledger_path: str = "pm_ledger.jsonl") -> dict:
    """Attribute a surfaced/leaked text copy back to a recipient.

    Strategy (most reliable first):
      1. embedded fingerprint → recipient id, cross-checked vs the sealed
         distribution ledger (CONFIRMED if the marked_hash also matches,
         FINGERPRINT-ONLY if the mark decodes but the bytes were altered)
      2. exact marked_hash match in the ledger (mark stripped but bytes intact)
      3. clean_hash match → we know the document but not the recipient
      4. nothing → UNTRACEABLE

    Verdicts:
      CONFIRMED         recipient id from mark AND a sealed record matches
      FINGERPRINT-ONLY  mark decodes to a recipient, but no exact byte match
                        (copy was edited after distribution) — still names a copy
      HASH-MATCH        no readable mark, but exact bytes match a sealed copy
      DOC-KNOWN         underlying document recognized, recipient unknown
      UNTRACEABLE       no mark, no matching record
    """
    dists = [e for e in pm._load_entries_safe(ledger_path)
             if e.get("_type") == "distribution"]
    marked_hash = hashlib.sha256(leaked_text.encode("utf-8")).hexdigest()[:16]
    clean_hash  = hashlib.sha256(_strip_marks(leaked_text).encode("utf-8")).hexdigest()[:16]

    mark_id = read_fingerprint(leaked_text)
    if mark_id is not None:
        exact = [e for e in dists if e.get("recipient") == mark_id
                 and e.get("marked_hash") == marked_hash]
        if exact:
            return {"verdict": "CONFIRMED", "recipient": mark_id,
                    "doc_id": exact[0].get("doc_id"),
                    "note": f"Embedded fingerprint → '{mark_id}', and the exact "
                            "marked bytes match a sealed distribution record."}
        sealed = [e for e in dists if e.get("recipient") == mark_id]
        return {"verdict": "FINGERPRINT-ONLY", "recipient": mark_id,
                "doc_id": sealed[0].get("doc_id") if sealed else None,
                "note": f"Embedded fingerprint → '{mark_id}'. Bytes were altered "
                        "after distribution (no exact match), but the mark names "
                        "this recipient's copy."}

    byte_hit = [e for e in dists if e.get("marked_hash") == marked_hash]
    if byte_hit:
        return {"verdict": "HASH-MATCH", "recipient": byte_hit[0].get("recipient"),
                "doc_id": byte_hit[0].get("doc_id"),
                "note": "No readable mark, but exact bytes match a sealed copy "
                        f"distributed to '{byte_hit[0].get('recipient')}'."}

    doc_hit = [e for e in dists if e.get("clean_hash") == clean_hash]
    if doc_hit:
        recips = sorted({e.get("recipient") for e in doc_hit})
        return {"verdict": "DOC-KNOWN", "recipient": None,
                "doc_id": doc_hit[0].get("doc_id"),
                "note": f"Document recognized (distributed to {len(recips)} "
                        "recipient(s)) but the leaked copy carries no mark — "
                        "recipient unknown. Mark was stripped or re-typed."}

    return {"verdict": "UNTRACEABLE", "recipient": None, "doc_id": None,
            "note": "No fingerprint and no matching distribution record."}
