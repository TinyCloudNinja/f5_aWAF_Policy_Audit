"""
Utility functions: logging setup, helpers, retry logic, and compliance tier helpers.

Changelog: Scoring refactor – added tier calculation utilities and color constants
for the graduated 4-tier compliance model used by WAF and Bot Defense comparators.
"""
import logging
import os
import re
import time
import functools
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


# ── Logging ────────────────────────────────────────────────────────────────────

class _MaskFilter(logging.Filter):
    """Remove passwords/tokens from log records.

    Patterns cover:
    - JSON-style  "password": "..."  and  "token": "..."
    - YAML-style  password: ...
    - HTTP header X-F5-Auth-Token: <value>
    - Query/form  password=<value>
    - Raw bearer  Bearer <token-like value>
    - Exception messages that echo the raw requests body
    """
    _PATTERNS = [
        # JSON double-quoted values
        (re.compile(r'("password"\s*:\s*")[^"]*(")', re.I),         r'\g<1>***MASKED***\g<2>'),
        (re.compile(r'("token"\s*:\s*")[^"]*(")', re.I),            r'\g<1>***MASKED***\g<2>'),
        # YAML / plain key: value (unquoted or single-quoted)
        (re.compile(r"(password\s*:\s*['\"]?)[^\s'\"#,}]+", re.I), r'\g<1>***MASKED***'),
        # HTTP header (request/response logs)
        (re.compile(r'(X-F5-Auth-Token\s*:\s*)\S+', re.I),         r'\g<1>***MASKED***'),
        # Query string / form body
        (re.compile(r'(password=)[^\s&"\']+', re.I),                r'\g<1>***MASKED***'),
        # Bearer tokens in Authorization headers
        (re.compile(r'(Bearer\s+)\S+', re.I),                       r'\g<1>***MASKED***'),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        # Render the final formatted message (including % substitution) so that
        # sensitive values embedded in the args are also caught.
        msg = record.getMessage()
        for pat, repl in self._PATTERNS:
            msg = pat.sub(repl, msg)
        record.msg = msg
        record.args = ()
        return True


class _ColorFormatter(logging.Formatter):
    """ANSI-colored console formatter."""
    RESET = "\x1b[0m"
    COLORS = {
        logging.DEBUG:    "\x1b[36m",   # cyan
        logging.INFO:     "\x1b[32m",   # green
        logging.WARNING:  "\x1b[33m",   # yellow
        logging.ERROR:    "\x1b[31m",   # red
        logging.CRITICAL: "\x1b[35m",   # magenta
    }

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelno, self.RESET)
        record.levelname = f"{color}{record.levelname:<8}{self.RESET}"
        return super().format(record)


def setup_logging(verbose: bool, output_dir: str, mode: str = "waf") -> logging.Logger:
    """Configure root logger for console + file output."""
    log_level = logging.DEBUG if verbose else logging.INFO
    logger = logging.getLogger("f5_auditor")
    logger.setLevel(log_level)
    logger.handlers.clear()
    mask = _MaskFilter()

    # Console handler
    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    ch.setFormatter(_ColorFormatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S"))
    ch.addFilter(mask)
    logger.addHandler(ch)

    # File handler
    Path(output_dir).mkdir(mode=0o700, parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    mode_prefix = "BOT" if mode.lower() == "bot" else "WAF"
    log_path = Path(output_dir) / f"{mode_prefix}_audit_{ts}.log"
    fh = logging.FileHandler(log_path, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-8s [%(name)s] %(message)s"
    ))
    fh.addFilter(mask)
    logger.addHandler(fh)

    return logger


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"f5_auditor.{name}")


# ── Retry decorator ────────────────────────────────────────────────────────────

def retry(max_attempts: int = 3, base_delay: float = 2.0,
          exceptions: tuple = (Exception,)):
    """Exponential-backoff retry decorator."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            log = get_logger("retry")
            delay = base_delay
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    if attempt == max_attempts:
                        raise
                    log.warning(
                        "Attempt %d/%d failed (%s: %s). Retrying in %.1fs …",
                        attempt, max_attempts, type(exc).__name__, exc, delay
                    )
                    time.sleep(delay)
                    delay *= 2
        return wrapper
    return decorator


# ── Filename helpers ───────────────────────────────────────────────────────────

def sanitize_filename(name: str) -> str:
    """Replace path separators and spaces; keep alphanumeric and safe chars."""
    return re.sub(r'[^\w\-.]', '_', name).strip('_')


def policy_export_filename(full_path: str, export_format: str = "xml") -> str:
    """
    Build a safe export filename from a policy fullPath.
    /Common/my_waf -> WAF_Common_my_waf_20260303T1430.xml
    """
    clean = full_path.lstrip('/')
    sanitized = sanitize_filename(clean.replace('/', '_'))
    ts = datetime.now().strftime("%Y%m%dT%H%M")
    return f"WAF_{sanitized}_{ts}.{export_format}"


# ── Misc helpers ───────────────────────────────────────────────────────────────

def ensure_dir(path: str) -> Path:
    """Create a directory (and parents) with owner-only permissions (0o700).

    Policy exports and audit reports contain sensitive WAF configuration data.
    Restricting access to the process owner prevents other local users from
    reading them on shared systems.
    """
    p = Path(path)
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    return p


def normalize_full_path(path: str, partition: str = "Common") -> str:
    """Ensure fullPath always starts with /partition/."""
    if not path.startswith('/'):
        return f"/{partition}/{path}"
    return path


def iso_timestamp() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def human_bool(value) -> str:
    if isinstance(value, bool):
        return "Enabled" if value else "Disabled"
    return str(value)


# ── Compliance tier helpers (scoring presentation layer utility) ───────────────

# Default tier band definitions for 4-level model
TIER_RED = "RED"
TIER_AMBER = "AMBER"
TIER_YELLOW = "YELLOW"
TIER_GREEN = "GREEN"

_TIER_BANDS = [
    {
        "name": TIER_RED,
        "label": "Non-Compliant",
        "emoji": "🔴",
        "color": "#dc3545",
        "min": 0,
        "max": 49,
    },
    {
        "name": TIER_AMBER,
        "label": "Review Required",
        "emoji": "🟠",
        "color": "#fd7e14",
        "min": 50,
        "max": 74,
    },
    {
        "name": TIER_YELLOW,
        "label": "Monitor",
        "emoji": "🟡",
        "color": "#ffc107",
        "min": 75,
        "max": 89,
    },
    {
        "name": TIER_GREEN,
        "label": "Compliant",
        "emoji": "🟢",
        "color": "#28a745",
        "min": 90,
        "max": 100,
    },
]


@dataclass(frozen=True)
class TierInfo:
    """Represents a compliance tier derived from a score.

    The tier calculation is pure and side-effect free, making it easy to unit test.
    The green threshold can be overridden for backward compatibility with the
    legacy --pass-threshold CLI flag.
    """

    name: str
    label: str
    color: str
    emoji: str
    score: float
    is_hard_fail: bool
    circuit_breakers: list[str]


# ── Violation ID alias table ───────────────────────────────────────────────────
#
# F5 BIG-IP renamed several violation machine IDs between software versions.
# The XML export format preserves the *old* id= attribute while the iControl
# REST API (/blocking-settings/violations) returns the *new* name.  Normalizing
# at parse time ensures both XML baselines and REST targets use the same ID.
_XML_VIOL_ID_ALIASES: Dict[str, str] = {
    "MALFORMED_JSON": "MALFORMED_JSON_DATA",
    "MALFORMED_GWT":  "MALFORMED_GWT_DATA",
    "MALFORMED_XML":  "MALFORMED_XML_DATA",
}


def score_to_tier(score: float, circuit_breakers: Optional[List[str]] = None, green_threshold: float = 90.0) -> TierInfo:
    """Map a numeric score to a tier.

    Args:
        score: Final compliance score (0–100 after any circuit breaker capping).
        circuit_breakers: List of triggered circuit breaker names (empty if none).
        green_threshold: Lower bound for the Green tier (default 90.0) to support
            backward compatibility with the legacy --pass-threshold flag. Only the
            Green/YELLOW boundary shifts; Amber/Red remain at 74/49 respectively.

    Returns:
        TierInfo with name/label/color/emoji and whether any circuit breaker fired.
    """

    cb_list = circuit_breakers or []
    # Adjust the yellow/green boundary if the caller overrides the green threshold.
    bands = list(_TIER_BANDS)
    if green_threshold != 90.0:
        # Clamp to sane range
        g_min = max(0, min(100, green_threshold))
        for band in bands:
            if band["name"] == TIER_GREEN:
                band["min"] = g_min
            if band["name"] == TIER_YELLOW:
                band["max"] = max(74, g_min - 1)
    # Select band
    chosen = bands[0]
    for band in bands:
        if band["min"] <= score <= band["max"]:
            chosen = band
            break
    return TierInfo(
        name=chosen["name"],
        label=chosen["label"],
        color=chosen["color"],
        emoji=chosen["emoji"],
        score=score,
        is_hard_fail=bool(cb_list),
        circuit_breakers=cb_list,
    )
