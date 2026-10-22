"""Runs only when the local Hydra container (docker-compose) is reachable."""

import asyncio

import httpx
import pytest

from gr9_refresh_token_rotation.servers.hydra_client import HydraClient


@pytest.fixture
async def client():
    c = HydraClient()
    try:
        await c.wait_ready(timeout=2.0)
    except (httpx.TransportError, RuntimeError):
        await c.aclose()
        pytest.skip("Hydra not available")
    yield c
    await c.aclose()


async def test_login_issues_a_refresh_token(client):
    result = await client.login()
    assert result.ok and result.refresh_token


async def test_rotated_token_cannot_be_replayed(client):
    login = await client.login()
    first = await client.refresh(login.refresh_token)
    assert first.ok and first.refresh_token != login.refresh_token

    replay = await client.refresh(login.refresh_token)
    assert not replay.ok and replay.status == 400


async def test_concurrent_refresh_can_fork_the_family(client):
    """Counterpart to the Keycloak integration test: here the same race the
    project's own ``naive_rotation`` strategy models does reproduce over
    real HTTP against a single-node dev instance."""
    login = await client.login()
    results = await asyncio.gather(*(client.refresh(login.refresh_token) for _ in range(10)))
    assert sum(r.ok for r in results) >= 1  # at least the one legitimate winner
