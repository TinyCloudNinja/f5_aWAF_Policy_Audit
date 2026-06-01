"""
Unit tests for the pure data-transformation helpers in src/main.py:
  - _reduce_baseline_for_inspector
  - _inspector_to_target_dict

These helpers bridge the XML-parsed baseline and the REST-inspected target into
the shape compare_policies expects.  They are the seam where representation
differences (enforcement-mode location, default-state violations) can introduce
false drift, so they are covered directly here.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.main import _reduce_baseline_for_inspector, _inspector_to_target_dict


# ── _reduce_baseline_for_inspector ──────────────────────────────────────────────

class TestReduceBaselineEnforcementMode:
    def test_prefers_blocking_section_over_general_default(self):
        """Full exports often carry a placeholder <general> (defaulting to
        'transparent') while the real mode lives in <blocking>.  The reduced
        baseline must report the blocking section's mode."""
        baseline = {
            "general":  {"enforcementMode": "transparent"},
            "blocking": {"enforcement_mode": "blocking", "violations": []},
        }
        reduced = _reduce_baseline_for_inspector(baseline)
        assert reduced["general"]["enforcementMode"] == "blocking"

    def test_falls_back_to_general_when_no_blocking_section(self):
        baseline = {"general": {"enforcementMode": "blocking"}, "blocking": {}}
        reduced = _reduce_baseline_for_inspector(baseline)
        assert reduced["general"]["enforcementMode"] == "blocking"

    def test_defaults_transparent_when_neither_present(self):
        reduced = _reduce_baseline_for_inspector({})
        assert reduced["general"]["enforcementMode"] == "transparent"

    def test_violations_fall_back_to_blocking_section(self):
        viols = [{"id": "VIRUS_DETECTED", "name": "VIRUS_DETECTED", "block": True}]
        baseline = {"blocking": {"enforcement_mode": "blocking", "violations": viols}}
        reduced = _reduce_baseline_for_inspector(baseline)
        assert reduced["blocking-settings"]["violations"] == viols


# ── _inspector_to_target_dict ───────────────────────────────────────────────────

class TestInspectorToTargetDict:
    def _inspection(self, all_list):
        return {
            "enforcementMode": "blocking",
            "learningMode":    "automatic",
            "violations":      {"learn": [], "alarm": [], "block": [], "all": all_list},
            "signatureSets":   [],
        }

    def test_all_violations_included_with_flags(self):
        """Default-state (all-False) violations from the 'all' list must appear in
        the target dict so the comparator does not report them as missing."""
        all_list = [
            {"name": "VIRUS_DETECTED",   "description": "Virus detected",
             "alarm": False, "block": False, "learn": False},
            {"name": "RESPONSE_SCRUBBING", "description": "Response scrubbing",
             "alarm": True, "block": True, "learn": True},
        ]
        target = _inspector_to_target_dict(self._inspection(all_list))
        viols = {v["name"]: v for v in target["blocking-settings"]["violations"]}
        assert set(viols) == {"VIRUS_DETECTED", "RESPONSE_SCRUBBING"}
        assert viols["VIRUS_DETECTED"]["block"] is False
        assert viols["RESPONSE_SCRUBBING"]["block"] is True

    def test_falls_back_to_per_flag_lists_when_no_all_key(self):
        """Backward-compat: older inspector output without an 'all' key is rebuilt
        from the per-flag lists."""
        inspection = {
            "enforcementMode": "blocking",
            "learningMode":    "disabled",
            "violations": {
                "learn": [{"name": "A", "description": "a"}],
                "alarm": [{"name": "A", "description": "a"}],
                "block": [{"name": "B", "description": "b"}],
            },
            "signatureSets": [],
        }
        target = _inspector_to_target_dict(inspection)
        viols = {v["name"]: v for v in target["blocking-settings"]["violations"]}
        assert viols["A"]["learn"] is True and viols["A"]["alarm"] is True
        assert viols["A"]["block"] is False
        assert viols["B"]["block"] is True

    def test_enforcement_mode_propagated(self):
        target = _inspector_to_target_dict(self._inspection([]))
        assert target["general"]["enforcementMode"] == "blocking"
