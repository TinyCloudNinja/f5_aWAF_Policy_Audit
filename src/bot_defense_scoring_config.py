"""
Posture scoring configuration for Bot Defense profile triage.

Separate from the WAF scoring config (scoring_config.py) — Bot Defense profiles
have different risk signals, drift vectors, and standalone posture indicators.
Adjust weights and thresholds here without touching logic code.
"""
from __future__ import annotations

BOT_SCORING_CONFIG: dict = {
    # ── Status ladder ──────────────────────────────────────────────────────────
    # Four triage bands, most-urgent first. Identical labels to the WAF bands
    # so Bot Defense and WAF items share the same status vocabulary.
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
    # Must be <= bands[0]["max"] (39) to guarantee Review Now placement.
    "hard_trigger_cap": 39,

    # ── Hard triggers ──────────────────────────────────────────────────────────
    # Any single trigger pins the profile to Review Now regardless of score.
    "hard_triggers": {
        "NO_VIRTUAL_SERVERS": {
            "label": "Profile not attached to any virtual server",
            "description": (
                "The Bot Defense profile is configured but not applied to any "
                "virtual server — it is protecting nothing. Bot traffic passes "
                "through uninspected."
            ),
            "remediation": (
                "Attach the profile to a virtual server directly or via an LTM "
                "policy rule with a botDefense action."
            ),
        },
        "BOT_TRANSPARENT_MODE": {
            "label": "Enforcement mode is Transparent (detection only, not blocking)",
            "description": (
                "The profile is in transparent mode: bots are logged but never "
                "blocked or challenged. Automation can probe bot-defense decisions "
                "without consequence."
            ),
            "remediation": (
                "Switch enforcementMode to Blocking once the profile has been tuned "
                "and the false-positive rate is acceptable."
            ),
        },
        "BOT_NO_TEETH": {
            "label": "All high-risk bot class overrides set to alarm/none — no mitigation",
            "description": (
                "Every class override for confirmed-malicious and automated bot "
                "categories is configured to alarm or none instead of a blocking "
                "or challenge action. The profile detects these bots but performs "
                "no mitigation against them."
            ),
            "remediation": (
                "For high-risk bot categories (malicious-bot, dos-tool, scanner, "
                "web-scraper), set each class override action to block, captcha, "
                "or rate-limit rather than alarm or none."
            ),
        },
    },

    # ── Drift category caps ────────────────────────────────────────────────────
    # Per section_category maximum deduction from loosening drift DiffItems.
    # Prevents any single drift category from dominating the score.
    # Keys match the categories returned by _bot_drift_category().
    "drift_category_caps": {
        "class_actions": 20,   # class override action downgrades — primary poisoning vector
        "whitelist":     16,   # whitelist entries added / IP ranges broadened
        "mobile_sdk":     8,   # mobile SDK posture loosened vs baseline
        "signatures":     8,   # signatures moved to staging / actions weakened
        "bot_defense":   12,   # core enforcement/mode/mitigation settings
        "general":        6,   # other settings
        "default":        4,   # catch-all for unlisted categories
    },

    # ── Standalone posture signals ─────────────────────────────────────────────
    # Evaluated directly from the target profile — no baseline required.
    # Sorted by relative risk weight (highest first for documentation clarity).
    "categories": {

        # ── High-weight: sees threats but doesn't act ──────────────────────────

        "browser_mitigation_weak": {
            "label": "Browser mitigation action not enforcing for untrusted browsers",
            "description": (
                "browserMitigationAction is set to a non-blocking value (alarm, "
                "none, or detect). Untrusted browsers are logged but not challenged "
                "or blocked."
            ),
            "remediation": (
                "Set browserMitigationAction to block or captcha to enforce "
                "mitigation against untrusted browser traffic."
            ),
            "flat": 12,
            "max_deduction": 12,
        },

        "dos_anomaly_alarm_only": {
            "label": "DoS/Anomaly mitigation set to alarm-only",
            "description": (
                "dosAttackStrictMitigation is disabled, or all configured anomaly "
                "overrides use detect-only actions. DoS patterns are logged but "
                "not rate-limited or blocked."
            ),
            "remediation": (
                "Enable dosAttackStrictMitigation and set high-confidence anomaly "
                "category overrides to block or rate-limit rather than detect-only."
            ),
            "flat": 10,
            "max_deduction": 10,
        },

        "api_strict_mitigation_off": {
            "label": "API access strict mitigation disabled",
            "description": (
                "apiAccessStrictMitigation is explicitly disabled. API endpoints "
                "protected by this profile do not receive strict bot-mitigation "
                "enforcement."
            ),
            "remediation": (
                "Enable apiAccessStrictMitigation for profiles protecting API "
                "endpoints to ensure automated client access is enforced strictly."
            ),
            "flat": 8,
            "max_deduction": 8,
        },

        "staged_signatures": {
            "label": "Bot signatures accumulating in staging (detection gap)",
            "description": (
                "Bot signatures in staging generate log entries but do not block "
                "matched traffic. A large staging backlog indicates enforcement "
                "coverage gaps."
            ),
            "remediation": (
                "Review staged signatures and promote mature entries to enforced "
                "mode. Reserve staging for newly-added signatures during initial "
                "evaluation, not as a permanent state."
            ),
            "per_item": 1,
            "max_deduction": 10,
        },

        # ── Lower-weight: permissive hygiene ───────────────────────────────────

        "cross_domain_permissive": {
            "label": "Cross-domain requests set to allow-all",
            "description": (
                "crossDomainRequests is permissive (allow-all) rather than "
                "validating origin domains. Cross-origin automation is not "
                "challenged or restricted."
            ),
            "remediation": (
                "Set crossDomainRequests to validate or restrict origins not in "
                "the site-domains list to prevent cross-origin bot abuse."
            ),
            "flat": 5,
            "max_deduction": 5,
        },

        "mobile_sdk_loose": {
            "label": "Mobile SDK security posture loosened",
            "description": (
                "One or more mobile SDK security flags are permissive: rooted or "
                "jailbroken devices are allowed, emulators are allowed, any "
                "Android/iOS package is permitted, or debugger-enabled devices "
                "are not blocked."
            ),
            "remediation": (
                "Disable allowJailbrokenDevices, allowAndroidRootedDevice, "
                "allowEmulators, allowAnyAndroidPackage, and allowAnyIosPackage. "
                "Enable blockDebuggerEnabledDevice."
            ),
            "per_flag": 2,
            "max_deduction": 8,
        },

        "template_relaxed": {
            "label": "Bot Defense template set to relaxed",
            "description": (
                "The profile uses the relaxed template, which provides the least "
                "restrictive Bot Defense posture. Protection level: "
                "relaxed < balanced < strict."
            ),
            "remediation": (
                "Move to the balanced or strict template where the traffic profile "
                "supports it. Use class or signature overrides to carve out "
                "specific exceptions."
            ),
            "flat": 4,
            "max_deduction": 4,
        },

        "deviceid_weak": {
            "label": "Device identification effectively disabled",
            "description": (
                "deviceidMode is set to a weak or disabled value. Device "
                "fingerprinting is not generated or not used for bot decisions, "
                "reducing detection accuracy for returning bots."
            ),
            "remediation": (
                "Set deviceidMode to generate-if-session-not-present or higher "
                "to enable persistent device fingerprinting for bot analysis."
            ),
            "flat": 4,
            "max_deduction": 4,
        },

        "grace_period_extended": {
            "label": "Grace period or enforcement readiness period extended",
            "description": (
                "A long gracePeriod or enforcementReadinessPeriod creates a soft "
                "window where bot traffic is not enforced while signatures or "
                "settings are warming up."
            ),
            "remediation": (
                "Keep grace periods short on production profiles (hours, not days). "
                "Long windows significantly reduce enforcement coverage during "
                "the warm-up period."
            ),
            # Threshold: > 86400 seconds (1 day) is considered extended.
            # Tune this in the detector function if needed.
            "flat": 3,
            "max_deduction": 3,
        },

        "challenge_transparent_off": {
            "label": "performChallengeInTransparent disabled",
            "description": (
                "performChallengeInTransparent is disabled. When other conditions "
                "push the profile toward transparent behavior, challenges will not "
                "be issued, reducing bot signal quality and detection accuracy."
            ),
            "remediation": (
                "Enable performChallengeInTransparent so that challenges are "
                "issued even in transparent mode, maintaining detection fidelity."
            ),
            "flat": 2,
            "max_deduction": 2,
        },
    },
}
