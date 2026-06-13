# 🔎 Provenance Mirror — Signal Guide

> **Audience**: anyone deciding whether a file's origin can be trusted, or
> tracing which copy of a document leaked. This guide explains every signal,
> when it fires, and how to read the verdict.
>
> **Companion**: [README](../README.md) · [CHANGELOG](../CHANGELOG.md)
> **한국어**: [GUIDE_KO.md](GUIDE_KO.md)

---

## Philosophy: verifier, not detector

A **detector** guesses "fake" from pixels — a learned classifier in an arms
race. A **verifier** checks deterministic provenance & integrity signals —
signatures, declared origin, container structure. Provenance Mirror is a
verifier, and its most valuable output is the honest one a detector refuses to
give: **`UNVERIFIED` — "I don't know."**

| Direction | Example | Verdict effect |
|---|---|---|
| False positive | An unsigned real photo branded "AI fake" | We return `UNVERIFIED`, never accuse |
| Missed signal | A leak with no provenance | `tamper_anchor` / `trace` still attribute it |

An unsigned real photo is `UNVERIFIED`, not "fake". Refusing to brand the
innocent is the whole point.

---

## The two capabilities

```
verify(file)                         trace(leaked_text)
  ├─ ① c2pa_manifest                   ├─ read embedded fingerprint
  ├─ ② generator_meta                  ├─ cross-check distribution ledger
  ├─ ③ ai_watermark        ┌──────────┤   → CONFIRMED / FINGERPRINT-ONLY /
  ├─ ④ tamper_anchor ──────┘ shared      DOC-KNOWN / HASH-MATCH / UNTRACEABLE
  └─ ⑤ format_integrity      ledger
        │                              distribute(text, recipient)
        ▼                                └─ embed invisible mark + seal record
   verdict (honesty-first synthesis)
```

Both write to the same chain-hashed ledger, so `④ tamper_anchor` and `trace`
share the re-attribution machinery.

---

## Signal reference

Each probe returns a `Signal(probe, direction, detail)` where `direction` is one
of `AUTHENTIC` / `SYNTHETIC` / `TAMPERED` / `NONE`. A silent probe (`NONE`)
proves nothing — absence of a signal is never evidence of fakery.

### ① `c2pa_manifest_check(data: bytes) → Signal`

**Reads**: an embedded C2PA / Content Credentials manifest.

```python
from provmirror import pm
pm.c2pa_manifest_check(img_bytes)
# AUTHENTIC  — manifest present (signature chain NOT yet crypto-verified)
# SYNTHETIC  — manifest present AND declares AI origin (trainedAlgorithmicMedia)
# NONE       — no manifest found
```

A manifest that *declares* AI origin (the generator signed "I made this with
ML") flips the signal to `SYNTHETIC`. **PoC limit**: detects manifest presence
by byte-scan; does not yet verify the cryptographic signature chain (needs the
`c2pa` library — documented TODO).

### ② `generator_meta_check(data: bytes) → Signal`

**Reads**: known AI-generator fingerprints left in EXIF/XMP/PNG-text.

```python
pm.generator_meta_check(b"...Software: Stable Diffusion XL...")
# SYNTHETIC — "AI-generator signature in metadata: Stable Diffusion"
```

Markers include Stable Diffusion, Midjourney, DALL·E, Adobe Firefly, ComfyUI,
NovelAI, and more. Deterministic scan — presence is a signal, absence proves
nothing (returns `NONE`).

### ③ `ai_watermark_check(data: bytes) → Signal`

**Reads**: declared AI watermark / training-media markers.

**PoC limit**: detects *declared* markers only. Real steganographic watermarks
(e.g. SynthID) are private to the vendor detector and are a NOT-IMPLEMENTED
stub. Absence means "couldn't check", not "no watermark".

### ④ `tamper_anchor_check(ledger_path, file_hash, origin) → Signal`

**Reads**: the ledger — has this exact content been sealed before under a
*different* declared origin?

```python
# reuters.com seals a photo; later troll-farm.ru claims the same bytes
pm.verify("photo.jpg", origin="reuters.com")     # ⚪ UNVERIFIED, sealed
pm.verify("photo.jpg", origin="troll-farm.ru")   # 🔴 TAMPERED (④ fires)
```

Direct port of measure-mirror's `anchor`: the SHA-256 of the bytes is the
identity. Same bytes + different origin = re-attribution / laundering →
`TAMPERED`. Only fires when you pass an `origin`.

### ⑤ `format_integrity_check(data: bytes) → Signal`

**Reads**: container structure (JPEG/PNG magic & end markers, multiple SOI).

```python
pm.format_integrity_check(truncated_jpeg)   # TAMPERED — missing EOI marker
pm.format_integrity_check(spliced_jpeg)     # TAMPERED — multiple SOI markers
pm.format_integrity_check(clean_png)        # NONE — structure intact
```

Intact structure is `NONE` (not itself a provenance signal). Only clear
structural breakage returns `TAMPERED`.

---

## Verdict synthesis

`verify()` collapses the five signals into one verdict. The priority order
encodes the honesty policy:

| Priority | Verdict | Condition |
|---|---|---|
| 1 | `TAMPERED` | any signal points TAMPERED |
| 2 | `CONFLICTING` | AUTHENTIC and SYNTHETIC both present |
| 3 | `SYNTHETIC` | an AI-origin signal present |
| 4 | `AUTHENTIC-SIGNED` | a provenance signature present, nothing contradicts |
| 5 | `UNVERIFIED` | nothing — the honest default |

```python
res = pm.verify("photo.jpg", ledger_path="pm_ledger.jsonl", origin="reuters.com")
pm.report(res)
#   Verdict: ⚪ UNVERIFIED
#   No usable signal. UNKNOWN — this is NOT evidence of fakery.
#   ⚪ [① c2pa-manifest] ...
```

`verify()` seals the verdict (file hash, origin, per-signal directions) into the
ledger unless `seal=False`. The ledger is chain-hashed and append-only.

---

## Leak tracing

### `distribute(text, *, recipient, doc_id, ledger_path) → dict`

Fingerprint a copy for one recipient and seal the distribution record.

```python
from provmirror import tracing as tr
out = tr.distribute(DOC, recipient="jebi", doc_id="q3-report")
send_to_jebi(out["marked_text"])   # visually identical to DOC
```

The mark is a zero-width-character bit-string of the recipient id, inserted
between words. `clean_hash` identifies the document (mark-independent);
`marked_hash` identifies this exact copy.

### `trace(leaked_text, *, ledger_path) → dict`

Attribute a surfaced copy. Strategy, most reliable first:

| Verdict | When |
|---|---|
| `CONFIRMED` | mark decodes to a recipient AND exact bytes match a sealed record |
| `FINGERPRINT-ONLY` | mark names a recipient, but the copy was edited afterwards |
| `HASH-MATCH` | no readable mark, but exact distributed bytes match a sealed copy |
| `DOC-KNOWN` | document recognized, recipient unknown (mark stripped/re-typed) |
| `UNTRACEABLE` | no mark, no matching record |

```python
tr.trace(leaked_text)
# {"verdict": "CONFIRMED", "recipient": "jebi", "doc_id": "q3-report", ...}
```

### `fingerprint_text` / `read_fingerprint`

The low-level codec, if you want to mark/decode without sealing:

```python
marked = tr.fingerprint_text(DOC, "jebi")   # invisible mark
tr.read_fingerprint(marked)                  # → "jebi"
tr._strip_marks(marked) == DOC               # True — visually identical
```

**Honest limits**: survives copy/paste; does NOT survive re-typing, OCR,
screenshots, or a deliberate zero-width strip. Attribution names a *copy*, not a
person. Obfuscation, not encryption.

---

## Workflows

### Workflow 1: verify an inbound file

```python
from provmirror import pm
res = pm.verify("/inbox/screenshot.png", ledger_path="pm_ledger.jsonl",
                origin="slack:#general")
pm.report(res)
# UNVERIFIED → unknown (don't trust as proof, don't brand as fake)
# SYNTHETIC  → AI-origin metadata found
# TAMPERED   → re-attribution or structural breakage
```

### Workflow 2: distribute a confidential doc with leak tracing

```python
from provmirror import tracing as tr
LEDGER = "~/mirror_ledgers/provenance.jsonl"
for who in ["jebi", "sonnet", "ext-partner-07"]:
    out = tr.distribute(report_text, recipient=who, doc_id="q3", ledger_path=LEDGER)
    deliver(who, out["marked_text"])
# later: tr.trace(leaked, ledger_path=LEDGER) → who
```

### Workflow 3: detect content re-attribution

```python
# seal every published asset under its true origin
pm.verify("press_photo.jpg", origin="our-newsroom", ledger_path=LEDGER)
# if the same bytes resurface under a different claimed origin → TAMPERED
```

---

## Quick reference

| # | Signal | Direction | Fires via |
|---|---|---|---|
| ① | `c2pa_manifest_check` | AUTHENTIC / SYNTHETIC | `verify` |
| ② | `generator_meta_check` | SYNTHETIC | `verify` |
| ③ | `ai_watermark_check` | SYNTHETIC | `verify` |
| ④ | `tamper_anchor_check` | TAMPERED | `verify(origin=...)` |
| ⑤ | `format_integrity_check` | TAMPERED | `verify` |
| — | `distribute` / `trace` | — | leak tracing |
| — | `badge` | — | verdict badge (markdown/svg) |

**Verdict severity**: `TAMPERED` > `SYNTHETIC` > `CONFLICTING` >
`AUTHENTIC-SIGNED` > `UNVERIFIED`.

---

*Built as a sister to measure-mirror, under one discipline:*
*prove what you can, say "unknown" about the rest.*
