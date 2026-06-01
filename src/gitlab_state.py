"""
Git/GitLab-backed policy state management.

This module lets the auditor:
  1) Sync a local clone of a GitLab repository.
  2) Load per-policy/profile "source-of-truth" files from that repo.
  3) Archive run artifacts (exports + reports + manifest) into the repo.
  4) Update source-of-truth files with the latest audited state.
  5) Commit/push changes.

All Git operations are best-effort. Failures are logged and do not prevent
the core BIG-IP audit workflow from completing.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ._deprecated.policy_parser import parse_policy  # transitional: XML SoT fallback only
from .utils import ensure_dir, get_logger, sanitize_filename


class GitLabStateManager:
    """Manage policy/report state in a Git-backed repository."""

    def __init__(
        self,
        repo_url: str,
        local_dir: str,
        branch: str = "main",
        auto_push: bool = False,
    ):
        self.repo_url = repo_url
        self.repo_dir = Path(local_dir).resolve()
        self.branch = branch
        self.auto_push = auto_push
        self.log = get_logger("gitlab_state")

    # ── Git sync ───────────────────────────────────────────────────────────────

    def sync_from_remote(self) -> bool:
        """
        Ensure the local repository exists and is up to date.

        Returns True on success, False on failure.
        """
        try:
            if (self.repo_dir / ".git").exists():
                self.log.info("Syncing local policy-state repo: %s", self.repo_dir)
                self._git(["checkout", self.branch], check=False)
                self._git(["fetch", "origin", self.branch], check=False)
                self._git(["pull", "--ff-only", "origin", self.branch], check=False)
            else:
                self.log.info("Cloning policy-state repo into %s", self.repo_dir)
                ensure_dir(self.repo_dir.parent)
                self._run(
                    [
                        "git",
                        "clone",
                        "--branch",
                        self.branch,
                        "--single-branch",
                        self.repo_url,
                        str(self.repo_dir),
                    ],
                    check=True,
                )

            self._ensure_layout()
            return True
        except Exception as exc:
            self.log.warning("Git repo sync failed; source-of-truth features disabled: %s", exc)
            return False

    def _ensure_layout(self) -> None:
        ensure_dir(self.repo_dir / "source_of_truth" / "waf")
        ensure_dir(self.repo_dir / "source_of_truth" / "bot")
        ensure_dir(self.repo_dir / "runs" / "waf")
        ensure_dir(self.repo_dir / "runs" / "bot")

    # ── Source-of-truth loading ────────────────────────────────────────────────

    def load_waf_source_of_truth(self, policy_full_path: str) -> Tuple[Optional[Dict], str]:
        """Load source-of-truth WAF policy from repo, if present.

        Tries JSON (new API-normalized format) first, then falls back to
        XML (legacy export format).  Logs a migration hint on XML fallback.
        """
        json_path = self._sot_file_path("waf", policy_full_path, "json")
        if json_path.exists():
            try:
                with json_path.open("r", encoding="utf-8") as fh:
                    return json.load(fh), f"gitlab:{json_path.relative_to(self.repo_dir)}"
            except Exception as exc:
                self.log.warning("Could not read source-of-truth WAF JSON %s: %s", json_path, exc)

        xml_path = self._sot_file_path("waf", policy_full_path, "xml")
        if xml_path.exists():
            self.log.info(
                "Loading XML source-of-truth for %s (migrate to JSON by running an audit "
                "with --gitlab-update-source-truth after upgrading to PolicyFetcher).",
                policy_full_path,
            )
            try:
                return parse_policy(str(xml_path)), f"gitlab:{xml_path.relative_to(self.repo_dir)}"
            except Exception as exc:
                self.log.warning("Could not parse source-of-truth WAF XML %s: %s", xml_path, exc)

        return None, ""

    def load_bot_source_of_truth(self, profile_full_path: str) -> Tuple[Optional[Dict], str]:
        """Load source-of-truth Bot Defense profile JSON from repo, if present."""
        path = self._sot_file_path("bot", profile_full_path, "json")
        if not path.exists():
            return None, ""
        try:
            with path.open("r", encoding="utf-8") as fh:
                return json.load(fh), f"gitlab:{path.relative_to(self.repo_dir)}"
        except Exception as exc:
            self.log.warning("Could not read source-of-truth Bot file %s: %s", path, exc)
            return None, ""

    # ── Run archival + source-of-truth update ──────────────────────────────────

    def archive_run(
        self,
        mode: str,
        output_dir: str,
        baseline_path: str,
        device_hostname: str,
        device_mgmt_ip: str,
        audited_count: int,
        failure_count: int,
    ) -> Optional[Path]:
        """Copy run artifacts into the repo under runs/<mode>/<timestamp>/..."""
        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        mode_key = "bot" if mode.lower() == "bot" else "waf"
        run_dir = ensure_dir(self.repo_dir / "runs" / mode_key / ts)

        src_out = Path(output_dir)
        reports_src = src_out / "reports"
        payload_src = src_out / ("bot-defense" if mode_key == "bot" else "exports")
        sot_reports_src = src_out / "source_of_truth" / "reports"

        if reports_src.exists():
            self._copy_tree(reports_src, run_dir / "reports")
        if payload_src.exists():
            self._copy_tree(payload_src, run_dir / payload_src.name)
        if sot_reports_src.exists():
            self._copy_tree(sot_reports_src, run_dir / "source_of_truth_reports")

        manifest = {
            "timestamp_utc": ts,
            "mode": mode_key,
            "baseline_path": baseline_path,
            "device": {
                "hostname": device_hostname,
                "mgmt_ip": device_mgmt_ip,
            },
            "audited_count": audited_count,
            "failure_count": failure_count,
        }
        (run_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2),
            encoding="utf-8",
        )
        self.log.info("Archived run artifacts to %s", run_dir)
        return run_dir

    def update_waf_source_of_truth(self, exported_policies: List[Dict]) -> int:
        """Update source_of_truth/waf files from exported policy XML files."""
        updated = 0
        for policy in exported_policies:
            local_path = policy.get("local_path")
            full_path = policy.get("fullPath", "")
            if not local_path or not full_path:
                continue
            src = Path(local_path)
            if not src.exists():
                continue
            dst = self._sot_file_path("waf", full_path, "xml")
            ensure_dir(dst.parent)
            shutil.copy2(src, dst)
            updated += 1
        if updated:
            self.log.info("Updated %d WAF source-of-truth file(s).", updated)
        return updated

    def update_bot_source_of_truth(self, fetched_profiles: List[Tuple[Dict, Dict]]) -> int:
        """Update source_of_truth/bot files from fetched profile JSON files."""
        updated = 0
        for profile_meta, _profile_data in fetched_profiles:
            local_path = profile_meta.get("local_path")
            full_path = profile_meta.get("fullPath", "")
            if not local_path or not full_path:
                continue
            src = Path(local_path)
            if not src.exists():
                continue
            dst = self._sot_file_path("bot", full_path, "json")
            ensure_dir(dst.parent)
            shutil.copy2(src, dst)
            updated += 1
        if updated:
            self.log.info("Updated %d Bot source-of-truth file(s).", updated)
        return updated

    # ── Commit/push ─────────────────────────────────────────────────────────────

    def commit_and_push(self, commit_message: Optional[str] = None) -> bool:
        """Commit any repo changes and push to origin when enabled."""
        try:
            if not self._has_changes():
                self.log.info("No Git changes to commit in policy-state repo.")
                return False

            msg = commit_message or (
                f"Policy audit sync {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%SZ')}"
            )
            self._git(["add", "."], check=True)
            self._git(["commit", "-m", msg], check=True)
            self.log.info("Committed policy-state updates.")

            if self.auto_push:
                self._git(["push", "origin", self.branch], check=True)
                self.log.info("Pushed policy-state updates to origin/%s.", self.branch)

            return True
        except Exception as exc:
            self.log.warning("Could not commit/push policy-state updates: %s", exc)
            return False

    def _has_changes(self) -> bool:
        out = self._git(["status", "--porcelain"], check=True)
        return bool(out.strip())

    # ── Paths/helpers ───────────────────────────────────────────────────────────

    def _sot_file_path(self, mode: str, full_path: str, ext: str) -> Path:
        mode_key = "bot" if mode.lower() == "bot" else "waf"
        rel = self._full_path_to_rel(full_path, ext)
        return self.repo_dir / "source_of_truth" / mode_key / rel

    def _full_path_to_rel(self, full_path: str, ext: str) -> Path:
        raw = (full_path or "").strip("/")
        parts = [sanitize_filename(p) for p in raw.split("/") if p]
        if not parts:
            parts = ["Common", "unknown"]
        stem = parts[-1] or "unknown"
        parent = parts[:-1]
        return Path(*parent) / f"{stem}.{ext}"

    def _copy_tree(self, src: Path, dst: Path) -> None:
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)

    # ── Subprocess wrappers ─────────────────────────────────────────────────────

    def _git(self, args: List[str], check: bool = True) -> str:
        return self._run(["git", "-C", str(self.repo_dir), *args], check=check)

    def _run(self, cmd: List[str], check: bool = True) -> str:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        if proc.returncode != 0 and check:
            raise RuntimeError(stderr or stdout or f"Command failed ({proc.returncode}): {' '.join(cmd)}")
        if proc.returncode != 0 and not check:
            self.log.debug("Command failed (ignored): %s :: %s", " ".join(cmd), stderr or stdout)
        return stdout
