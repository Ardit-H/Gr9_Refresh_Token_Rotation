"""Runs only when the local Keycloak container (docker-compose) is reachable."""

import httpx
import pytest

from gr9_refresh_token_rotation.servers.keycloak_client import KeycloakClient


@pytest.fixture
async def client():
    c = KeycloakClient()
    try:
        await c.wait_ready(timeout=2.0)
    except (httpx.TransportError, RuntimeError):
        await c.aclose()
        pytest.skip("Keycloak not available")
    yield c
    await c.aclose()


async def test_login_issues_a_refresh_token(client):
    result = await client.login()
    assert result.ok and result.refresh_token


async def test_rotated_token_cannot_be_replayed(client):
    """Strict rotation (refreshTokenMaxReuse=0): the superseded token is dead."""
    login = await client.login()
    first = await client.refresh(login.refresh_token)
    assert first.ok and first.refresh_token != login.refresh_token

    replay = await client.refresh(login.refresh_token)
    assert not replay.ok and replay.status == 400


async def test_concurrent_refresh_has_a_single_winner(client):
    """Companion to the in-process ``naive_rotation`` race test: on a single-
    node dev instance the real server's check-then-use is not observably
    racy over HTTP, unlike the project's own naive strategy."""
    import asyncio

    login = await client.login()
    results = await asyncio.gather(*(client.refresh(login.refresh_token) for _ in range(10)))
    assert sum(r.ok for r in results) == 1
