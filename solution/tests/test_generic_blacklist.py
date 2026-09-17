from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


FORBIDDEN = {
    "opspilot", "llm-stub", "notes-sync", "c2-sink",
    "asset-agent", "model-sim", "account-query", "canary-sink",
    "evil-assistant", "prompt-inject", "evil-mcp", "evil.example.com",
}


def test_generic_rules_do_not_contain_target_literals():
    generic = ROOT / "solution" / "rules" / "generic"
    text = "\n".join(path.read_text(encoding="utf-8").lower()
                      for path in generic.rglob("*") if path.is_file())
    assert not [literal for literal in FORBIDDEN if literal in text]


def test_generic_collectors_do_not_contain_target_literals():
    paths = list((ROOT / "solution" / "collectors").glob("*.py"))
    text = "\n".join(path.read_text(encoding="utf-8").lower() for path in paths)
    assert not [literal for literal in FORBIDDEN if literal in text]
