"""
BIG-IP iControl REST API client with token-based authentication,
automatic token refresh, retry/backoff, and chunked file transfer.
"""
import os
import time
import math
import logging
import threading
from pathlib import Path
from typing import Any, Dict, Optional

import requests
import urllib3

from .utils import get_logger, retry

_CHUNK_SIZE    = 1_048_576    # 1 MiB — F5 file-transfer hard limit
_MAX_DOWNLOAD  = 524_288_000  # 500 MiB — safety cap against unbounded streams


class AuthenticationError(Exception):
    pass


class BigIPClient:
    """
    Thin iControl REST wrapper.

    Authentication flow:
      POST /mgmt/shared/authn/login  →  token + timeout
      X-F5-Auth-Token header on every subsequent request
      Proactive refresh at 80% of token lifetime
    """

    _LOGIN_PATH = "/mgmt/shared/authn/login"
    _DEFAULT_TIMEOUT = 30
    _TRANSFER_TIMEOUT = 120

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        verify_ssl: bool = True,
        verbose: bool = False,
        login_provider: str = "tmos",
    ):
        self.base_url = f"https://{host}"
        self._username = username
        self._password = password
        self._verify_ssl = verify_ssl
        self._verbose = verbose
        self._login_provider = login_provider
        self.log = get_logger("bigip_client")

        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        self._session = requests.Session()
        self._session.verify = verify_ssl
        self._token: Optional[str] = None
        self._token_expiry: float = 0.0   # epoch seconds
        self._token_lifetime: int = 1200  # default 1200s; updated on login
        self._token_lock = threading.Lock()  # guards token refresh across threads

    # ── Authentication ─────────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Obtain a new auth token from BIG-IP."""
        self.log.debug("Authenticating as %s …", self._username)
        payload = {
            "username": self._username,
            "password": self._password,
            "loginProviderName": self._login_provider,
        }
        resp = self._session.post(
            self.base_url + self._LOGIN_PATH,
            json=payload,
            timeout=self._DEFAULT_TIMEOUT,
            verify=self._verify_ssl,
        )
        # Clear the password from the payload immediately after the request
        payload["password"] = ""
        if resp.status_code == 401:
            raise AuthenticationError(
                f"Authentication failed for user '{self._username}'. "
                "Check credentials and that the account has the "
                "Resource Administrator or Application Security Administrator role."
            )
        resp.raise_for_status()
        data = resp.json()
        token_obj = data.get("token", {})
        self._token = token_obj.get("token") or data.get("token")
        if not self._token:
            raise AuthenticationError("Login response did not include an auth token.")

        # BIG-IP returns timeout in seconds; default 1200
        self._token_lifetime = int(token_obj.get("timeout", 1200))
        # Proactive refresh at 80% of lifetime
        self._token_expiry = time.monotonic() + self._token_lifetime * 0.80
        self._session.headers.update({"X-F5-Auth-Token": self._token})
        self.log.debug(
            "Token obtained. Lifetime: %ds. Will refresh after %.0fs.",
            self._token_lifetime, self._token_lifetime * 0.80
        )


    def _ensure_token(self) -> None:
        """Re-authenticate if the token is absent or approaching expiry.

        Uses a lock so that concurrent export threads don't all trigger a
        simultaneous re-auth when the token expires mid-run.
        """
        with self._token_lock:
            if self._token is None or time.monotonic() >= self._token_expiry:
                self.log.info("Refreshing BIG-IP auth token …")
                self.authenticate()

    # ── Generic request ────────────────────────────────────────────────────────

    @retry(max_attempts=3, base_delay=2.0, exceptions=(requests.RequestException,))
    def _request(
        self,
        method: str,
        path: str,
        timeout: int = _DEFAULT_TIMEOUT,
        **kwargs,
    ) -> requests.Response:
        self._ensure_token()
        url = self.base_url + path
        if self._verbose:
            self.log.debug("→ %s %s", method.upper(), url)

        try:
            resp = self._session.request(method, url, timeout=timeout, **kwargs)
        except requests.ConnectionError as exc:
            raise requests.RequestException(
                f"Cannot reach BIG-IP at {self.base_url}: {exc}"
            ) from exc
        except requests.Timeout:
            raise requests.RequestException(
                f"Request to {url} timed out after {timeout}s"
            )

        if self._verbose:
            self.log.debug("← %d %s", resp.status_code, url)

        if resp.status_code == 401:
            # Token expired mid-flight; re-auth and let retry handle it
            self._token = None
            raise requests.RequestException("401 – token expired, re-authenticating")

        if resp.status_code == 404:
            raise requests.HTTPError(f"404 Not Found: {url}", response=resp)

        if resp.status_code >= 400:
            try:
                msg = resp.json().get("message", resp.text)
            except Exception:
                msg = resp.text
            raise requests.HTTPError(
                f"HTTP {resp.status_code} for {url}: {msg}", response=resp
            )

        return resp

    # ── Convenience wrappers ───────────────────────────────────────────────────

    def get(self, path: str, params: Optional[Dict] = None) -> Any:
        resp = self._request("GET", path, params=params)
        return resp.json()

    def post(self, path: str, data: Optional[Dict] = None) -> Any:
        resp = self._request("POST", path, json=data)
        return resp.json()

    # ── File transfer ──────────────────────────────────────────────────────────

    def upload_file(self, path: str, filepath: str) -> None:
        """
        Upload a local file to BIG-IP using 1 MiB Content-Range chunks.
        """
        filepath = Path(filepath)
        file_size = filepath.stat().st_size
        chunks = math.ceil(file_size / _CHUNK_SIZE)

        with open(filepath, "rb") as fh:
            for chunk_index in range(chunks):
                start = chunk_index * _CHUNK_SIZE
                end = min(start + _CHUNK_SIZE, file_size) - 1
                chunk = fh.read(_CHUNK_SIZE)
                headers = {
                    "Content-Type": "application/octet-stream",
                    "Content-Range": f"{start}-{end}/{file_size}",
                    "Content-Length": str(len(chunk)),
                }
                self._request(
                    "POST",
                    path,
                    timeout=self._TRANSFER_TIMEOUT,
                    data=chunk,
                    headers=headers,
                )
                self.log.debug(
                    "Uploaded chunk %d/%d for %s", chunk_index + 1, chunks, filepath.name
                )

    def download_file(
        self,
        path: str,
        local_path: str,
        expected_size: Optional[int] = None,
    ) -> int:
        """
        Download a file from BIG-IP, handling the 1 MiB chunk limit.

        The F5 ASM file-transfer endpoint returns at most 1,048,576 bytes per
        request and does NOT include a Content-Range response header that reveals
        the total file size.  Instead we loop until either:
          - we receive fewer bytes than the chunk size (end of file), or
          - total_written reaches expected_size (when provided by the caller).

        Returns the total number of bytes written.
        """
        local_path = Path(local_path)
        local_path.parent.mkdir(parents=True, exist_ok=True)

        total_written = 0
        with open(local_path, "wb") as fh:
            while True:
                start = total_written
                end   = start + _CHUNK_SIZE - 1
                if expected_size:
                    end = min(end, expected_size - 1)

                resp = self._request(
                    "GET",
                    path,
                    timeout=self._TRANSFER_TIMEOUT,
                    headers={"Content-Range": f"{start}-{end}/*"},
                )

                chunk = resp.content
                if not chunk:
                    break

                fh.write(chunk)
                total_written += len(chunk)
                self.log.debug(
                    "Downloaded %d bytes (total so far: %d%s)",
                    len(chunk),
                    total_written,
                    f" / {expected_size}" if expected_size else "",
                )

                # A partial chunk means we have reached the end of the file
                if len(chunk) < _CHUNK_SIZE:
                    break

                # Safety guard when expected_size is known
                if expected_size and total_written >= expected_size:
                    break

                # Hard cap — abort if response grows beyond the safety limit
                if total_written >= _MAX_DOWNLOAD:
                    raise requests.RequestException(
                        f"Download of {path!r} exceeded the {_MAX_DOWNLOAD // 1_048_576} MiB "
                        "safety limit. Aborting."
                    )

        self.log.debug("Download complete: %s (%d bytes)", local_path, total_written)
        return total_written

    def close(self) -> None:
        self._password = ""
        self._session.close()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_content_range_total(header: str) -> Optional[int]:
    """
    Extract total size from Content-Range header.
    E.g. 'bytes 0-1048575/3145728' → 3145728
    """
    if not header:
        return None
    parts = header.split('/')
    if len(parts) == 2 and parts[1] != '*':
        try:
            return int(parts[1])
        except ValueError:
            pass
    return None
