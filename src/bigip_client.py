"""
BIG-IP iControl REST API client with token-based authentication,
automatic token refresh, and retry/backoff.
"""
import os
import time
import logging
import threading
from typing import Any, Dict, Optional

import requests
import urllib3

from .utils import get_logger, retry


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

    def get_all(self, path: str, params: Optional[Dict] = None) -> list:
        """Fetch all pages from a paged iControl REST collection.

        Uses $top/$skip OData pagination until totalItems is exhausted.
        Raises on HTTP errors; returns an empty list for empty collections.
        """
        params = dict(params or {})
        params.setdefault("$top", 500)
        items: list = []
        skip = 0
        while True:
            params["$skip"] = skip
            data = self.get(path, params=params)
            page = data.get("items", [])
            items.extend(page)
            total = data.get("totalItems", len(items))
            if len(items) >= total:
                break
            skip += len(page)
            if not page:
                break  # safety: prevent infinite loop on empty page response
        return items

    def post(self, path: str, data: Optional[Dict] = None) -> Any:
        resp = self._request("POST", path, json=data)
        return resp.json()

    def close(self) -> None:
        self._password = ""
        self._session.close()
