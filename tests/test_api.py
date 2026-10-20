import httpx
import pytest

from gr9_refresh_token_rotation.api.main import create_app
from gr9_refresh_token_rotation.storage.token_store import InMemoryTokenStore


@pytest.fixture
async def client():
    app = create_app(InMemoryTokenStore())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


async def test_login_refresh_and_reuse(client):
    login = (await client.post("/login", params={"strategy": "atomic_rotation"})).json()

    ok = await client.post(
        "/refresh", params={"strategy": "atomic_rotation"},
        json={"refresh_token": login["refresh_token"]},
    )
    assert ok.status_code == 200

    replay = await client.post(
        "/refresh", params={"strategy": "atomic_rotation"},
        json={"refresh_token": login["refresh_token"]},
    )
    assert replay.status_code == 400
    assert replay.json()["detail"]["reuse_detected"] is True


async def test_unknown_strategy(client):
    r = await client.post("/login", params={"strategy": "bogus"})
    assert r.status_code == 404
