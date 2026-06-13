"""
Sync gate: every signal probe in pm.py is wired up everywhere it must be.

When you add a `*_check` signal probe to pm.py, this fails immediately if you
forget to: test it, mention it in both READMEs, document it in the GUIDEs, or
export it from the package. Also pins __version__ to pyproject.

Run:  pytest tests/test_sync.py -v
"""
import ast
import pathlib
import re

ROOT = pathlib.Path(__file__).parent.parent


# ─────────────────────────────────────────────────────────────
# Source of truth: signal probes (Signal-returning *_check funcs) in pm.py
# ─────────────────────────────────────────────────────────────
def _signal_probes() -> list[str]:
    src = (ROOT / "provmirror" / "pm.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    probes = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name.startswith("_") or not node.name.endswith("_check"):
            continue
        ann = ast.unparse(node.returns) if node.returns else ""
        if "Signal" in ann:
            probes.append(node.name)
    return probes


# Public API that must be exported + tested (probes + verify/trace surface)
def _public_api() -> list[str]:
    names = list(_signal_probes())
    names += ["verify", "badge", "report", "synthesize"]            # pm.py
    names += ["fingerprint_text", "read_fingerprint",
              "distribute", "trace"]                                 # tracing.py
    return names


PROBES = _signal_probes()
API = _public_api()


def test_probe_list_nonempty():
    assert len(PROBES) == 5, f"Expected 5 signal probes, found {len(PROBES)}: {PROBES}"


# ─────────────────────────────────────────────────────────────
# Gate 1: every signal probe is tested
# ─────────────────────────────────────────────────────────────
def test_probes_have_tests():
    test_src = "\n".join(
        (ROOT / "tests" / f).read_text(encoding="utf-8")
        for f in ("test_pm.py", "test_tracing.py"))
    missing = [p for p in PROBES if p not in test_src]
    assert not missing, "Untested signal probes:\n" + "\n".join(f"  ✗ {m}" for m in missing)


# ─────────────────────────────────────────────────────────────
# Gate 2: every signal probe is in both READMEs
# ─────────────────────────────────────────────────────────────
def test_probes_in_readmes():
    for readme in ("README.md", "README_KO.md"):
        text = (ROOT / readme).read_text(encoding="utf-8")
        # README tables use the short name (drop the _check suffix)
        missing = [p for p in PROBES if p not in text and p[:-6] not in text]
        assert not missing, f"{readme} missing:\n" + "\n".join(f"  ✗ {m}" for m in missing)


# ─────────────────────────────────────────────────────────────
# Gate 3: every signal probe is in both GUIDEs
# ─────────────────────────────────────────────────────────────
def test_probes_in_guides():
    for guide in ("docs/GUIDE.md", "docs/GUIDE_KO.md"):
        text = (ROOT / guide).read_text(encoding="utf-8")
        missing = [p for p in PROBES if p not in text]
        assert not missing, f"{guide} missing:\n" + "\n".join(f"  ✗ {m}" for m in missing)


# ─────────────────────────────────────────────────────────────
# Gate 4: full public API is exported from the package
# ─────────────────────────────────────────────────────────────
def test_public_api_exported():
    import provmirror
    missing = [n for n in API if not hasattr(provmirror, n) and not _in_tracing(n)]
    assert not missing, "Unexported public API:\n" + "\n".join(f"  ✗ {m}" for m in missing)


def _in_tracing(name: str) -> bool:
    from provmirror import tracing
    return hasattr(tracing, name)


# ─────────────────────────────────────────────────────────────
# Gate 5: __version__ matches pyproject.toml
# ─────────────────────────────────────────────────────────────
def test_version_matches_pyproject():
    import provmirror
    toml = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', toml, re.MULTILINE)
    assert m, "version not found in pyproject.toml"
    assert provmirror.__version__ == m.group(1), (
        f"Version drift: __init__={provmirror.__version__!r} pyproject={m.group(1)!r}")
