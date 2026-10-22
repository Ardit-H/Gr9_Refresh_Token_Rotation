"""HTTP client for the project's local Ory Hydra container.

Hydra has no resource-owner-password grant, so even the first token needs
the authorization-code flow, which normally runs through a separate login
and consent web app. This client drives Hydra's login/consent *admin* API
directly instead of running that app: it auto-approves the one test
subject (``alice``) the same way a real consent app would, but inline and
scriptable. Same ``login()``/``refresh()`` shape as ``keycloak_client.py``
so the harness scenarios can be pointed at either server.
"""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import dataclass

import httpx


@dataclass
class TokenResult:
    ok: bool
    access_token: str | None = None
    refresh_token: str | None = None
    status: int = 0
    error: str | None = None


class HydraClient:
    def __init__(
        self,
        public_url: str = "http://127.0.0.1:4444",
        admin_url: str = "http://127.0.0.1:4445",
        client_id: str = "gr9-client",
        client_secret: str = "gr9-secret",
        redirect_uri: str = "http://127.0.0.1:5555/callback",
        subject: str = "alice",
        scope: str = "openid offline_access",
    ) -> None:
        self._public = public_url
        self._admin = admin_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._subject = subject
        self._scope = scope
        # follow_redirects=False: each hop is inspected and resolved by hand.
        self._http = httpx.AsyncClient(follow_redirects=False, timeout=30)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def ensure_client(self) -> None:
        """Register the OAuth2 client if it does not already exist (idempotent)."""
        existing = await self._http.get(f"{self._admin}/admin/clients/{self._client_id}")
        if existing.status_code == 200:
            return
        await self._http.post(
            f"{self._admin}/admin/clients",
            json={
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "scope": self._scope,
                "redirect_uris": [self._redirect_uri],
                "token_endpoint_auth_method": "client_secret_post",
            },
        )

    async def wait_ready(self, timeout: float = 180.0) -> None:
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            try:
                health = await self._http.get(f"{self._public}/health/alive")
                if health.status_code == 200:
                    await self.ensure_client()
                    return
            except httpx.TransportError:
                pass
            await asyncio.sleep(2.0)
        raise RuntimeError("Hydra did not become ready in time")

    async def login(self) -> TokenResult:
        """Runs the full authorization-code flow for ``subject`` and exchanges
        the resulting code for the initial token pair."""
        state = secrets.token_urlsafe(16)
        r = await self._http.get(
            f"{self._public}/oauth2/auth",
            params={
                "client_id": self._client_id,
                "response_type": "code",
                "scope": self._scope,
                "redirect_uri": self._redirect_uri,
                "state": state,
            },
        )
        loc = httpx.URL(r.headers["location"])

        login_challenge = loc.params.get("login_challenge")
        if login_challenge is None:
            return TokenResult(ok=False, status=r.status_code, error="no_login_challenge")

        accept = await self._http.put(
            f"{self._admin}/admin/oauth2/auth/requests/login/accept",
            params={"login_challenge": login_challenge},
            json={"subject": self._subject, "remember": False},
        )
        r = await self._http.get(accept.json()["redirect_to"])
        loc = httpx.URL(r.headers["location"])

        consent_challenge = loc.params.get("consent_challenge")
        if consent_challenge is not None:
            accept = await self._http.put(
                f"{self._admin}/admin/oauth2/auth/requests/consent/accept",
                params={"consent_challenge": consent_challenge},
                json={
                    "grant_scope": self._scope.split(),
                    "grant_access_token_audience": [],
                    "remember": False,
                },
            )
            r = await self._http.get(accept.json()["redirect_to"])
            loc = httpx.URL(r.headers["location"])

        code = loc.params.get("code")
        if code is None:
            return TokenResult(ok=False, status=r.status_code, error=loc.params.get("error"))
        return await self._exchange({"grant_type": "authorization_code", "code": code,
                                      "redirect_uri": self._redirect_uri})

    async def refresh(self, refresh_token: str) -> TokenResult:
        return await self._exchange({"grant_type": "refresh_token", "refresh_token": refresh_token})

    async def _exchange(self, form: dict) -> TokenResult:
        r = await self._http.post(
            f"{self._public}/oauth2/token",
            data={"client_id": self._client_id, "client_secret": self._client_secret, **form},
        )
        body = r.json() if r.content else {}
        if r.status_code == 200:
            return TokenResult(
                ok=True,
                access_token=body.get("access_token"),
                refresh_token=body.get("refresh_token"),
                status=200,
            )
        return TokenResult(ok=False, status=r.status_code, error=body.get("error"))
