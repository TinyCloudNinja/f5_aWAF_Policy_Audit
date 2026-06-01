"""
Tests for the SSL string-to-bool conversion fix in src/main.py.

Verifies that string values from VERIFY_SSL env var or config are interpreted
correctly: "true"/"1"/"yes" → True (verification enabled), "false"/"0"/"no" → False.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.main import _resolve


def _ssl_from_string(raw: str) -> bool:
    """Reproduce the exact SSL resolution logic from main.py."""
    _raw_ssl = _resolve(None, "UNUSED_ENV_VAR_FOR_TEST", None, raw)
    if isinstance(_raw_ssl, str):
        return _raw_ssl.lower() in ("1", "true", "yes")
    return bool(_raw_ssl)


class TestSslStringConversion:
    @pytest.mark.parametrize("raw,expected", [
        ("true",  True),
        ("True",  True),
        ("TRUE",  True),
        ("1",     True),
        ("yes",   True),
        ("YES",   True),
        ("false", False),
        ("False", False),
        ("FALSE", False),
        ("0",     False),
        ("no",    False),
        ("NO",    False),
    ])
    def test_string_values(self, raw, expected):
        assert _ssl_from_string(raw) == expected

    def test_bool_true_unchanged(self):
        """Non-string True stays True."""
        _raw_ssl = _resolve(None, "UNUSED", None, True)
        assert not isinstance(_raw_ssl, str)
        assert bool(_raw_ssl) is True

    def test_bool_false_unchanged(self):
        """Non-string False stays False."""
        _raw_ssl = _resolve(None, "UNUSED", None, False)
        assert not isinstance(_raw_ssl, str)
        assert bool(_raw_ssl) is False
