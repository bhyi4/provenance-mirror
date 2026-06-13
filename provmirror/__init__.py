"""🔎 Provenance Mirror — content authenticity verifier (sister to measure-mirror)."""
from .pm import (
    verify, badge, report, synthesize,
    c2pa_manifest_check, generator_meta_check, ai_watermark_check,
    tamper_anchor_check, format_integrity_check,
    Signal, AUTHENTIC, SYNTHETIC, TAMPERED, NONE,
)

__all__ = [
    "verify", "badge", "report", "synthesize",
    "c2pa_manifest_check", "generator_meta_check", "ai_watermark_check",
    "tamper_anchor_check", "format_integrity_check",
    "Signal", "AUTHENTIC", "SYNTHETIC", "TAMPERED", "NONE",
]
__version__ = "0.1.0"
