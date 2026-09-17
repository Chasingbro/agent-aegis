"""P3 rules layering and target isolation tests."""

from __future__ import annotations

import sys
from pathlib import Path

SOLUTION = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOLUTION))


def test_legacy_rules_remain_compatible():
    from rules import loader

    legacy = loader.load()
    assert len(loader.injection_patterns()) >= 20
    assert len(loader.load_rules("AgentRange-player", use_profile=False)["injection_patterns"]) >= 20
    assert "all-access" in legacy["weak_value_patterns"]


def test_profile_is_target_specific_and_generic_has_no_target_literal():
    from rules import loader

    profile = loader.load_rules("AgentRange-player", use_profile=True)
    generic = loader.load_rules("simulated-target", use_profile=False)
    assert profile["profile_id"] == "agent-range"
    assert "all-access" in profile["weak_value_patterns"]
    assert "all-access" not in generic["weak_value_patterns"]
    assert "notes-sync" not in "\n".join(str(value) for value in generic.values())


def test_unknown_target_does_not_fallback_to_agent_range_profile():
    from rules import loader

    unknown = loader.load_rules("some-new-target", use_profile=True)
    generic = loader.load_rules("some-new-target", use_profile=False)
    assert unknown == generic


def test_rule_cache_does_not_cross_targets():
    from rules import loader

    first = loader.load_rules("AgentRange-player", use_profile=True)
    second = loader.load_rules("simulated-target", use_profile=False)
    third = loader.load_rules("AgentRange-player", use_profile=True)
    assert "agent_literals" in first
    assert "agent_literals" not in second
    assert first == third


def test_generic_accessors_accept_explicit_context():
    from rules import loader

    assert "all-access" in loader.weak_value_patterns("AgentRange-player")
    assert "all-access" not in loader.weak_value_patterns("simulated-target", use_profile=False)
