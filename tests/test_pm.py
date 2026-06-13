"""Tests for provenance-mirror — synthetic byte fixtures, no real images needed."""
from __future__ import annotations
import os
from provmirror import pm

# Minimal valid containers
JPEG_OK  = b"\xff\xd8\xff\xe0" + b"\x00" * 40 + b"\xff\xd9"
PNG_OK   = b"\x89PNG\r\n\x1a\n" + b"\x00" * 30 + b"IEND\xae\x42\x60\x82"


def jpeg_with(meta: bytes) -> bytes:
    """Realistic JPEG: metadata lives BEFORE the EOI (0xFFD9) marker."""
    return b"\xff\xd8\xff\xe0" + b"\x00" * 20 + meta + b"\xff\xd9"


def png_with(meta: bytes) -> bytes:
    """Realistic PNG: text metadata lives BEFORE the IEND chunk."""
    return b"\x89PNG\r\n\x1a\n" + b"\x00" * 20 + meta + b"IEND\xae\x42\x60\x82"


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


# ─── individual signal probes ────────────────────────────────

def test_c2pa_authentic():
    s = pm.c2pa_manifest_check(JPEG_OK + b"jumbf c2pa Content Credentials")
    assert s.direction == pm.AUTHENTIC


def test_c2pa_ai_assertion_flips_synthetic():
    s = pm.c2pa_manifest_check(b"c2pa ... trainedAlgorithmicMedia ...")
    assert s.direction == pm.SYNTHETIC


def test_c2pa_absent_is_none():
    s = pm.c2pa_manifest_check(JPEG_OK)
    assert s.direction == pm.NONE


def test_generator_meta_detects_known_tool():
    s = pm.generator_meta_check(JPEG_OK + b"Software: Stable Diffusion v1.5")
    assert s.direction == pm.SYNTHETIC
    assert "Stable Diffusion" in s.detail


def test_generator_meta_clean_is_none():
    s = pm.generator_meta_check(JPEG_OK + b"Software: Canon EOS R5")
    assert s.direction == pm.NONE


def test_watermark_declared():
    s = pm.ai_watermark_check(b"... SynthID ...")
    assert s.direction == pm.SYNTHETIC


def test_format_integrity_truncated_jpeg():
    s = pm.format_integrity_check(b"\xff\xd8\xff\xe0" + b"\x00" * 20)  # no EOI
    assert s.direction == pm.TAMPERED
    assert "EOI" in s.detail


def test_format_integrity_double_soi():
    spliced = b"\xff\xd8\xff\xe0" + b"\x00" * 10 + b"\xff\xd8\xff\xe0" + b"\x00" * 10 + b"\xff\xd9"
    s = pm.format_integrity_check(spliced)
    assert s.direction == pm.TAMPERED
    assert "splice" in s.detail or "SOI" in s.detail


def test_format_integrity_intact_png():
    s = pm.format_integrity_check(PNG_OK)
    assert s.direction == pm.NONE


def test_tamper_anchor_conflict(tmp_path):
    """Same file_hash sealed under a different origin → TAMPERED."""
    ledger = str(tmp_path / "l.jsonl")
    f = _write(tmp_path, "x.jpg", JPEG_OK)
    pm.verify(f, ledger_path=ledger, origin="reuters.com")  # seal hash@reuters
    fh = __import__("hashlib").sha256(JPEG_OK).hexdigest()
    s = pm.tamper_anchor_check(ledger, fh, "troll-farm.ru")
    assert s.direction == pm.TAMPERED
    assert "origin" in s.detail


def test_tamper_anchor_no_conflict_same_origin(tmp_path):
    """Same origin re-sealing the same bytes is fine → NONE."""
    ledger = str(tmp_path / "l.jsonl")
    f = _write(tmp_path, "x.jpg", JPEG_OK)
    pm.verify(f, ledger_path=ledger, origin="reuters.com")
    fh = __import__("hashlib").sha256(JPEG_OK).hexdigest()
    s = pm.tamper_anchor_check(ledger, fh, "reuters.com")
    assert s.direction == pm.NONE


# ─── verdict synthesis (honesty-first priority) ──────────────

def test_synthesize_tamper_wins():
    sigs = [pm.Signal("a", pm.AUTHENTIC, ""), pm.Signal("t", pm.TAMPERED, "")]
    assert pm.synthesize(sigs) == "TAMPERED"


def test_synthesize_conflict():
    sigs = [pm.Signal("a", pm.AUTHENTIC, ""), pm.Signal("s", pm.SYNTHETIC, "")]
    assert pm.synthesize(sigs) == "CONFLICTING"


def test_synthesize_synthetic():
    sigs = [pm.Signal("s", pm.SYNTHETIC, ""), pm.Signal("n", pm.NONE, "")]
    assert pm.synthesize(sigs) == "SYNTHETIC"


def test_synthesize_authentic():
    sigs = [pm.Signal("a", pm.AUTHENTIC, ""), pm.Signal("n", pm.NONE, "")]
    assert pm.synthesize(sigs) == "AUTHENTIC-SIGNED"


def test_synthesize_unverified_is_default():
    """The honesty guarantee: all-silent → UNVERIFIED, never a fakery claim."""
    sigs = [pm.Signal("n", pm.NONE, "")] * 5
    assert pm.synthesize(sigs) == "UNVERIFIED"


# ─── verify() end-to-end ─────────────────────────────────────

def test_verify_clean_photo_is_unverified_not_fake(tmp_path):
    """A clean, unsigned real photo must NOT be branded fake — the core value."""
    f = _write(tmp_path, "real.jpg", jpeg_with(b"Canon EOS R5"))
    res = pm.verify(f, ledger_path=str(tmp_path / "l.jsonl"))
    assert res["verdict"] == "UNVERIFIED"
    assert "NOT evidence of fakery" in res["note"]


def test_verify_ai_image_synthetic(tmp_path):
    f = _write(tmp_path, "ai.png", png_with(b"Midjourney v6"))
    res = pm.verify(f, ledger_path=str(tmp_path / "l.jsonl"))
    assert res["verdict"] == "SYNTHETIC"


def test_verify_signed_authentic(tmp_path):
    f = _write(tmp_path, "signed.jpg", jpeg_with(b"Content Credentials jumbf"))
    res = pm.verify(f, ledger_path=str(tmp_path / "l.jsonl"))
    assert res["verdict"] == "AUTHENTIC-SIGNED"


def test_verify_seals_ledger_chain(tmp_path):
    ledger = str(tmp_path / "l.jsonl")
    f = _write(tmp_path, "x.jpg", JPEG_OK)
    res = pm.verify(f, ledger_path=ledger)
    assert "ledger_entry" in res
    assert len(res["ledger_entry"]["seal"]) == 16
    assert res["ledger_entry"]["prev_seal"] == "GENESIS"


def test_verify_tamper_anchor_origin_conflict(tmp_path):
    """Same bytes sealed under two origins → ④ TAMPERED on the second."""
    ledger = str(tmp_path / "l.jsonl")
    f = _write(tmp_path, "x.jpg", JPEG_OK)
    pm.verify(f, ledger_path=ledger, origin="reuters.com")
    res2 = pm.verify(f, ledger_path=ledger, origin="troll-farm.ru")
    assert res2["verdict"] == "TAMPERED"
    assert any(s["direction"] == pm.TAMPERED and "origin" in s["detail"]
               for s in res2["signals"])


def test_verify_deterministic(tmp_path):
    """Same bytes + same ledger state → identical verdict."""
    f = _write(tmp_path, "x.png", PNG_OK + b"DALL-E 3")
    r1 = pm.verify(f, ledger_path=str(tmp_path / "a.jsonl"))
    r2 = pm.verify(f, ledger_path=str(tmp_path / "b.jsonl"))
    assert r1["verdict"] == r2["verdict"] == "SYNTHETIC"
    assert r1["file_hash"] == r2["file_hash"]


# ─── badge ───────────────────────────────────────────────────

def test_badge_markdown(tmp_path):
    f = _write(tmp_path, "ai.png", png_with(b"Midjourney"))
    res = pm.verify(f, ledger_path=str(tmp_path / "l.jsonl"), seal=False)
    b = pm.badge(res)
    assert "SYNTHETIC" in b and "orange" in b


def test_badge_svg_unverified(tmp_path):
    f = _write(tmp_path, "x.jpg", JPEG_OK)
    res = pm.verify(f, ledger_path=str(tmp_path / "l.jsonl"), seal=False)
    b = pm.badge(res, fmt="svg")
    assert b.startswith("<svg") and "UNVERIFIED" in b
