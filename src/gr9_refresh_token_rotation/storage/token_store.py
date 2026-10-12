"""Token-state backends.

The store is the shared state that the refresh strategies read and write.
Atomicity of ``compare_and_set_status`` is what separates atomic rotation
from naive rotation, so every backend must implement it as a single
indivisible operation.
"""

from __future__ import annotations

import dataclasses
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass

ACTIVE = "active"
USED = "used"
REVOKED = "revoked"


def hash_token(token: str) -> str:
    """Tokens are stored hashed, never in clear text."""
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass
class TokenRecord:
    token_hash: str
    family_id: str
    status: str = ACTIVE
    used_at: float | None = None  # when the token was consumed (grace window)


class TokenStore(ABC):
    @abstractmethod
    async def put(self, record: TokenRecord) -> None: ...

    @abstractmethod
    async def get(self, token_hash: str) -> TokenRecord | None: ...

    @abstractmethod
    async def set_status(self, token_hash: str, status: str) -> None:
        """Unconditional write (used by the naive, non-atomic strategy)."""

    @abstractmethod
    async def set_used_at(self, token_hash: str, ts: float) -> None:
        """Record when a token was consumed (needed by the grace window)."""

    @abstractmethod
    async def compare_and_set_status(
        self, token_hash: str, expected: str, new: str
    ) -> bool:
        """Atomically change status only if it currently equals ``expected``."""

    @abstractmethod
    async def revoke_family(self, family_id: str) -> None: ...

    @abstractmethod
    async def is_family_revoked(self, family_id: str) -> bool: ...

    @abstractmethod
    async def family_tokens(self, family_id: str) -> list[TokenRecord]:
        """All tokens ever issued in a family (used to detect forking)."""

    @abstractmethod
    async def clear(self) -> None: ...


class InMemoryTokenStore(TokenStore):
    """Single-process store for unit tests and fast harness runs.

    Every method is a plain dict operation with no ``await`` inside, so
    ``compare_and_set_status`` is atomic with respect to the asyncio loop.
    """

    def __init__(self) -> None:
        self._tokens: dict[str, TokenRecord] = {}
        self._revoked_families: set[str] = set()

    async def put(self, record: TokenRecord) -> None:
        self._tokens[record.token_hash] = dataclasses.replace(record)

    async def get(self, token_hash: str) -> TokenRecord | None:
        rec = self._tokens.get(token_hash)
        return None if rec is None else dataclasses.replace(rec)

    async def set_status(self, token_hash: str, status: str) -> None:
        if token_hash in self._tokens:
            self._tokens[token_hash].status = status

    async def set_used_at(self, token_hash: str, ts: float) -> None:
        if token_hash in self._tokens:
            self._tokens[token_hash].used_at = ts

    async def compare_and_set_status(
        self, token_hash: str, expected: str, new: str
    ) -> bool:
        rec = self._tokens.get(token_hash)
        if rec is None or rec.status != expected:
            return False
        rec.status = new
        return True

    async def revoke_family(self, family_id: str) -> None:
        self._revoked_families.add(family_id)

    async def is_family_revoked(self, family_id: str) -> bool:
        return family_id in self._revoked_families

    async def family_tokens(self, family_id: str) -> list[TokenRecord]:
        return [
            dataclasses.replace(r)
            for r in self._tokens.values()
            if r.family_id == family_id
        ]

    async def clear(self) -> None:
        self._tokens.clear()
        self._revoked_families.clear()


# Redis compare-and-set: runs as one indivisible Lua script on the server.
_CAS_LUA = """
local cur = redis.call('HGET', KEYS[1], 'status')
if cur == ARGV[1] then
  redis.call('HSET', KEYS[1], 'status', ARGV[2])
  return 1
end
return 0
"""


class RedisTokenStore(TokenStore):
    """Redis-backed store; ``compare_and_set_status`` is a Lua script."""

    def __init__(self, client, prefix: str = "gr9") -> None:
        self._r = client
        self._p = prefix
        self._cas = client.register_script(_CAS_LUA)

    def _tok(self, h: str) -> str:
        return f"{self._p}:tok:{h}"

    def _fam(self, f: str) -> str:
        return f"{self._p}:fam:{f}"

    def _rev(self, f: str) -> str:
        return f"{self._p}:revoked:{f}"

    async def put(self, record: TokenRecord) -> None:
        await self._r.hset(
            self._tok(record.token_hash),
            mapping={"family_id": record.family_id, "status": record.status},
        )
        await self._r.sadd(self._fam(record.family_id), record.token_hash)

    async def get(self, token_hash: str) -> TokenRecord | None:
        data = await self._r.hgetall(self._tok(token_hash))
        if not data:
            return None
        used_at = data.get("used_at")
        return TokenRecord(
            token_hash,
            data["family_id"],
            data["status"],
            float(used_at) if used_at is not None else None,
        )

    async def set_status(self, token_hash: str, status: str) -> None:
        await self._r.hset(self._tok(token_hash), "status", status)

    async def set_used_at(self, token_hash: str, ts: float) -> None:
        await self._r.hset(self._tok(token_hash), "used_at", repr(ts))

    async def compare_and_set_status(
        self, token_hash: str, expected: str, new: str
    ) -> bool:
        return bool(await self._cas(keys=[self._tok(token_hash)], args=[expected, new]))

    async def revoke_family(self, family_id: str) -> None:
        await self._r.set(self._rev(family_id), "1")

    async def is_family_revoked(self, family_id: str) -> bool:
        return bool(await self._r.exists(self._rev(family_id)))

    async def family_tokens(self, family_id: str) -> list[TokenRecord]:
        hashes = await self._r.smembers(self._fam(family_id))
        out = []
        for h in hashes:
            rec = await self.get(h)
            if rec:
                out.append(rec)
        return out

    async def clear(self) -> None:
        async for key in self._r.scan_iter(match=f"{self._p}:*"):
            await self._r.delete(key)
