"""
Posture scoring configuration for the WAF policy triage model.

All weights, thresholds, and band definitions live here.
Adjust these values to tune scoring without touching logic code.
"""
from __future__ import annotations

POSTURE_SCORING_CONFIG: dict = {
    # ── Status ladder ──────────────────────────────────────────────────────────
    # Four triage bands, most-urgent first.  Thresholds are inclusive.
    "bands": [
        {
            "name": "REVIEW_NOW",
            "label": "Review Now",
            "min": 0,
            "max": 39,
            "color": "#dc3545",
            "emoji": "🔴",
        },
        {
            "name": "REVIEW_SOON",
            "label": "Review Soon",
            "min": 40,
            "max": 64,
            "color": "#fd7e14",
            "emoji": "🟠",
        },
        {
            "name": "MONITOR",
            "label": "Monitor",
            "min": 65,
            "max": 84,
            "color": "#ffc107",
            "emoji": "🟡",
        },
        {
            "name": "ALIGNED",
            "label": "Aligned",
            "min": 85,
            "max": 100,
            "color": "#28a745",
            "emoji": "🟢",
        },
    ],

    # Maximum Posture Score when any hard trigger fires.
    # Must be <= bands[0]["max"] to guarantee "Review Now" placement.
    "hard_trigger_cap": 39,

    # ── Hard triggers ──────────────────────────────────────────────────────────
    # Any one of these overrides the numeric score to "Review Now".
    "hard_triggers": {
        "NO_VIRTUAL_SERVERS": {
            "label": "Policy not bound to any virtual server",
            "description": (
                "The policy is configured but not attached to any traffic path — "
                "it is enforcing nothing."
            ),
            "remediation": (
                "Attach the policy to a virtual server to begin enforcement."
            ),
        },
        "TRANSPARENT_MODE": {
            "label": "Enforcement mode is Transparent (log-only, not blocking)",
            "description": (
                "The policy logs violations but does not block them. "
                "Attackers can probe WAF decisions without consequence."
            ),
            "remediation": (
                "Switch enforcement mode to Blocking once the policy is tuned "
                "and the false-positive rate is acceptable."
            ),
        },
        "NO_SIGNATURE_SETS": {
            "label": "No attack signature sets applied",
            "description": (
                "Without signature sets the WAF has no pattern-matching coverage — "
                "virtually all signature-based attacks pass through undetected."
            ),
            "remediation": (
                "Apply at least the Generic Detection Signatures set and any "
                "tech-stack-specific sets relevant to the protected application."
            ),
        },
    },

    # ── Drift category caps ────────────────────────────────────────────────────
    # Per section_category maximum deduction from loosening DiffItems.
    # Prevents a single category of findings from dominating the score.
    # section_category values come from DiffItem.section_category as set by
    # the comparator functions.
    "drift_category_caps": {
        "signatures":     20,   # disabled sigs, removed/unblocked sets
        "blocking":       20,   # violation block→alarm
        "enforcement":     0,   # mode change is a hard trigger — no extra deduction
        "data_guard":     16,   # data guard features disabled
        "ip_intelligence": 12,  # IP intelligence disabled / categories relaxed
        "bot_defense":    12,   # embedded bot defense disabled
        "whitelist":       8,   # unauthorized IP whitelist additions
        "policy_builder": 10,   # policy builder loosened vs baseline
        "general":         8,   # general settings
        "default":         6,   # catch-all for unlisted categories
    },

    # ── Standalone posture signals ─────────────────────────────────────────────
    # These are computed directly from the target policy and do not require a
    # baseline comparison.  Each has an independent cap for leniency.
    "categories": {

        # High-weight: primary attack-poisoning vector signals

        "staging_ratio": {
            "label": "High share of signatures in staging rather than enforced",
            "description": (
                "Signatures in staging are evaluated but do not block attacks — they "
                "log only.  A large staging ratio severely reduces enforcement coverage."
            ),
            "remediation": (
                "Review staged signatures and promote to enforced mode. Use staging "
                "narrowly on new signature sets during initial rollout, not broadly."
            ),
            "max_deduction": 20,
            # (min_fraction_staged, deduction_points) — first matching row wins
            "thresholds": [
                (0.75, 20),
                (0.50, 14),
                (0.25,  8),
                (0.10,  3),
            ],
        },

        "blocking_disabled": {
            "label": "All blocking disabled on the policy",
            "description": (
                "Every violation and signature block flag is off.  The policy is in "
                "enforcing mode but will not actually stop any traffic."
            ),
            "remediation": (
                "Enable blocking on at least the highest-confidence violations and "
                "signature sets.  Investigate why all block flags were disabled."
            ),
            "flat": 15,
            "max_deduction": 15,
        },

        "policy_builder_auto": {
            "label": "Policy Builder in fully-automatic mode",
            "description": (
                "The Automatic Policy Builder can be exploited: an attacker shaping "
                "traffic can train the WAF to accept real attacks, causing signatures "
                "to be staged or disabled and entities to be widened — automatically."
            ),
            "remediation": (
                "Set Policy Builder to manual review mode so that a WAF admin must "
                "approve each suggestion before it is applied.  This is especially "
                "critical on internet-facing policies."
            ),
            "flat": 10,
            "max_deduction": 10,
        },

        "accepted_learning_widened": {
            "label": "Accepted learning suggestions appear to have widened the policy",
            "description": (
                "Recently accepted Policy Builder suggestions relaxed enforcement — "
                "signatures were staged or disabled, violations were relaxed, or "
                "entities were widened.  This is the primary indicator of "
                "policy-poisoning drift."
            ),
            "remediation": (
                "Review accepted suggestions in the ASM audit log.  Selectively revert "
                "suggestions that loosened the policy, particularly those accepted "
                "during unusual traffic periods."
            ),
            "per_item": 3,
            "max_deduction": 12,
        },

        # Lower-weight: posture hygiene signals

        "loose_wildcard_entities": {
            "label": "Wildcard URLs or parameters bypass attack signature checks",
            "description": (
                "Catch-all entity definitions (wildcard URLs, star parameters) with "
                "attack-signature checks disabled let all unmatched traffic bypass "
                "targeted enforcement."
            ),
            "remediation": (
                "Replace wildcard entries with specific, well-scoped definitions where "
                "possible.  Ensure attack signature checks are enabled on any wildcards "
                "that must remain."
            ),
            "per_item": 2,
            "max_deduction": 8,
        },
    },
}
