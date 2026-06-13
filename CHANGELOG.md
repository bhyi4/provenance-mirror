# Changelog

All notable changes to Provenance Mirror are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.1.0] — 2026-06-12

First proof-of-concept. The **frame** is real and tested; the heavy crypto/ML
signals are explicitly marked as stubs (see README "Honest limitations").

### Added — content authenticity verifier (`provmirror.pm`)
- **5 signal probes** (each returns a `Signal` pointing AUTHENTIC / SYNTHETIC /
  TAMPERED / NONE):
  - ① `c2pa_manifest_check` — C2PA / Content Credentials manifest present?
    (AI-origin assertion inside flips it to SYNTHETIC)
  - ② `generator_meta_check` — known AI-generator fingerprint in metadata
  - ③ `ai_watermark_check` — declared AI watermark / training assertion
  - ④ `tamper_anchor_check` — same bytes previously sealed under a different
    origin (re-attribution / laundering signal)
  - ⑤ `format_integrity_check` — container structure intact? double-compression hint
- **`verify(file_path, *, ledger_path, origin, seal)`** — single entry point:
  runs all probes, synthesizes a verdict, seals it into a chain-hashed ledger.
- **Verdict synthesis** (honesty-first): `TAMPERED` > `SYNTHETIC` >
  `CONFLICTING` > `AUTHENTIC-SIGNED` > `UNVERIFIED`. The default `UNVERIFIED`
  means "unknown", never "fake" — refusing to brand the innocent is the value.
- **`badge(result, *, fmt)`** — verdict-colored markdown / SVG badge.

### Added — leak tracing (`provmirror.tracing`)
- **`fingerprint_text(text, recipient)`** / **`read_fingerprint(text)`** —
  invisible per-recipient zero-width-character mark (U+200B/U+200C, U+200D
  framing). Visually identical, survives copy/paste, decodes to the recipient id.
- **`distribute(text, *, recipient, doc_id, ledger_path)`** — fingerprint a copy
  and seal the distribution record.
- **`trace(leaked_text, *, ledger_path)`** — attribute a surfaced copy:
  `CONFIRMED` / `FINGERPRINT-ONLY` / `HASH-MATCH` / `DOC-KNOWN` / `UNTRACEABLE`.

### Added — tooling
- **CLI `pm`** (`pip install -e .`): `verify`, `distribute`, `trace`.
  Ledger default from `$PM_LEDGER`.
- Chain-hashed ledger ported from measure-mirror (`_seal`, `verify_chain` semantics).
- 33 tests (22 verifier + 11 tracing), all passing. Zero dependencies.

### Design
- **Verifier, not detector** — never claims "fake" from pixels; checks
  deterministic provenance/integrity signals only. Avoids the detector arms race.
- Same DNA as measure-mirror: zero-training, deterministic, sealed ledger,
  two-sided, honest about uncertainty.
