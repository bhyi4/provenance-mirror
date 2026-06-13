"""Tests for provenance-mirror traitor tracing (leak attribution)."""
from __future__ import annotations
from provmirror import tracing as tr

DOC = ("CONFIDENTIAL: the Q3 model achieves 0.91 on the held-out set. "
       "Do not distribute outside the research family.")


# ─── codec round-trip ────────────────────────────────────────

def test_fingerprint_is_invisible():
    marked = tr.fingerprint_text(DOC, "jebi")
    # visible text identical once zero-width chars are stripped
    assert tr._strip_marks(marked) == DOC
    # but the bytes differ (mark is embedded)
    assert marked != DOC


def test_read_fingerprint_round_trip():
    for who in ["jebi", "seara", "sonnet", "ext-partner-07"]:
        marked = tr.fingerprint_text(DOC, who)
        assert tr.read_fingerprint(marked) == who


def test_unmarked_text_reads_none():
    assert tr.read_fingerprint(DOC) is None


def test_remark_overwrites_cleanly():
    """Re-distributing a marked copy to a new recipient must not stack marks."""
    a = tr.fingerprint_text(DOC, "jebi")
    b = tr.fingerprint_text(a, "sonnet")     # re-mark the already-marked copy
    assert tr.read_fingerprint(b) == "sonnet"
    assert tr._strip_marks(b) == DOC


# ─── distribute + trace lifecycle ────────────────────────────

def test_distribute_seals_record(tmp_path):
    ledger = str(tmp_path / "l.jsonl")
    out = tr.distribute(DOC, recipient="jebi", doc_id="q3-report", ledger_path=ledger)
    assert out["recipient"] == "jebi"
    assert len(out["ledger_entry"]["seal"]) == 16
    assert out["marked_hash"] != out["clean_hash"]


def test_trace_confirmed(tmp_path):
    """The whole point: leaked copy → exact recipient, CONFIRMED."""
    ledger = str(tmp_path / "l.jsonl")
    jebi   = tr.distribute(DOC, recipient="jebi",   doc_id="q3", ledger_path=ledger)
    tr.distribute(DOC, recipient="sonnet", doc_id="q3", ledger_path=ledger)
    # jebi's copy surfaces on a public forum
    res = tr.trace(jebi["marked_text"], ledger_path=ledger)
    assert res["verdict"] == "CONFIRMED"
    assert res["recipient"] == "jebi"


def test_trace_distinguishes_recipients(tmp_path):
    ledger = str(tmp_path / "l.jsonl")
    a = tr.distribute(DOC, recipient="alice", doc_id="q3", ledger_path=ledger)
    b = tr.distribute(DOC, recipient="bob",   doc_id="q3", ledger_path=ledger)
    assert tr.trace(a["marked_text"], ledger_path=ledger)["recipient"] == "alice"
    assert tr.trace(b["marked_text"], ledger_path=ledger)["recipient"] == "bob"


def test_trace_fingerprint_only_after_edit(tmp_path):
    """Leaker edits the text but leaves the mark → still names the copy."""
    ledger = str(tmp_path / "l.jsonl")
    jebi = tr.distribute(DOC, recipient="jebi", doc_id="q3", ledger_path=ledger)
    edited = jebi["marked_text"].replace("0.91", "0.55")   # tamper with content
    res = tr.trace(edited, ledger_path=ledger)
    assert res["verdict"] == "FINGERPRINT-ONLY"
    assert res["recipient"] == "jebi"


def test_trace_hash_match_when_mark_stripped(tmp_path):
    """Mark stripped but exact distributed bytes resurface elsewhere."""
    ledger = str(tmp_path / "l.jsonl")
    jebi = tr.distribute(DOC, recipient="jebi", doc_id="q3", ledger_path=ledger)
    # attacker strips zero-width chars → back to clean DOC bytes
    stripped = tr._strip_marks(jebi["marked_text"])
    res = tr.trace(stripped, ledger_path=ledger)
    # no mark, clean bytes recognized as the document (recipient unknown)
    assert res["verdict"] == "DOC-KNOWN"
    assert res["recipient"] is None
    assert "stripped" in res["note"] or "re-typed" in res["note"]


def test_trace_untraceable(tmp_path):
    ledger = str(tmp_path / "l.jsonl")
    tr.distribute(DOC, recipient="jebi", doc_id="q3", ledger_path=ledger)
    res = tr.trace("totally unrelated leaked text", ledger_path=ledger)
    assert res["verdict"] == "UNTRACEABLE"


def test_distribution_chains_with_pm_verdicts(tmp_path):
    """Distribution records share the chain with pm.verify() — verify_chain
    over the same ledger stays intact."""
    from provmirror import pm
    ledger = str(tmp_path / "l.jsonl")
    tr.distribute(DOC, recipient="jebi", doc_id="q3", ledger_path=ledger)
    tr.distribute(DOC, recipient="bob",  doc_id="q3", ledger_path=ledger)
    entries = pm._load_entries_safe(ledger)
    assert len(entries) == 2
    # chain links hold
    assert entries[1]["prev_seal"] == entries[0]["seal"]
