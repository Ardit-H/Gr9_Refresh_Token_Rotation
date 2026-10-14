from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request

from gr9_refresh_token_rotation.strategies import STRATEGIES, RefreshStrategy

from .models import RefreshRequest, TokenResponse

router = APIRouter()


def _strategy(request: Request, name: str) -> RefreshStrategy:
    if name not in STRATEGIES:
        raise HTTPException(404, f"unknown strategy '{name}'")
    return request.app.state.strategies[name]


@router.post("/login", response_model=TokenResponse)
async def login(request: Request, strategy: str) -> TokenResponse:
    result = await _strategy(request, strategy).issue_initial()
    return TokenResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        family_id=result.family_id,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh(request: Request, body: RefreshRequest, strategy: str) -> TokenResponse:
    result = await _strategy(request, strategy).refresh(body.refresh_token)
    if not result.ok:
        # 400 invalid_grant per RFC 6749; the reuse flag is exposed for the harness.
        raise HTTPException(
            400,
            detail={"error": result.error, "reuse_detected": result.reuse_detected},
        )
    return TokenResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        family_id=result.family_id,
    )


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}
