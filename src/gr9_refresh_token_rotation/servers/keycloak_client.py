"""HTTP client for the project's local Keycloak container.

Wraps the OpenID Connect token endpoint (password grant for login,
refresh_token grant for rotation) so the harness scenarios in
``harness/scenarios.py`` can run unmodified against a real authorization
server instead of an in-process ``RefreshStrategy``.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx


@dataclass
class TokenResult:
    ok: bool
    access_token: str | None = None
    refresh_token: str | None = None
    status: int = 0
    error: str | None = None


class KeycloakClient:
    def __init__(
        self,
        base_url: str = "http://localhost:8081",
        realm: str = "gr9",
        client_id: str = "gr9-client",
        username: str = "alice",
        password: str = "alice",
    ) -> None:
        self._token_url = f"{base_url}/realms/{realm}/protocol/openid-connect/token"
        self._client_id = client_id
        self._username = username
        self._password = password
        self._http = httpx.AsyncClient(timeout=30)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def wait_ready(self, timeout: float = 180.0) -> None:
        """Poll the token endpoint until the realm import has completed."""
        loop = asyncio.get_event_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            try:
                if (await self.login()).ok:
                    return
            except httpx.TransportError:
                pass
            await asyncio.sleep(2.0)
        raise RuntimeError("Keycloak realm did not become ready in time")

    async def login(self) -> TokenResult:
        """Password grant: obtains the initial refresh token for the test user."""
        return await self._request(
            {
                "grant_type": "password",
                "client_id": self._client_id,
                "username": self._username,
                "password": self._password,
            }
        )

    async def refresh(self, refresh_token: str) -> TokenResult:
        return await self._request(
            {
                "grant_type": "refresh_token",
                "client_id": self._client_id,
                "refresh_token": refresh_token,
            }
        )

    async def _request(self, form: dict) -> TokenResult:
        resp = await self._http.post(self._token_url, data=form)
        body = resp.json() if resp.content else {}
        if resp.status_code == 200:
            return TokenResult(
                ok=True,
                access_token=body.get("access_token"),
                refresh_token=body.get("refresh_token"),
                status=200,
            )
        return TokenResult(ok=False, status=resp.status_code, error=body.get("error"))
