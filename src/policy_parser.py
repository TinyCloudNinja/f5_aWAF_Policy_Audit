"""
Backward-compatibility stub for src.policy_parser.

The full implementation has moved to src._deprecated.policy_parser (Phase 2).
This stub re-exports all public and private names so existing callers
(report_generator, test_policy_parser, test_policy_comparator) work unchanged
until Phase 4 migrates _XML_VIOL_ID_ALIASES into utils.py and removes this file.
"""
# Re-export everything — wildcard covers public names; explicit imports
# cover private helpers that tests access directly (e.g. _parse_blocking_violation).
from src._deprecated.policy_parser import *  # noqa: F401,F403
from src._deprecated.policy_parser import (  # noqa: F401
    parse_policy,
    get_policy_metadata,
    _XML_VIOL_ID_ALIASES,
    _parse_blocking_violation,
)
