"""Minimal async client for the OPA REST API (OPA runs as a sidecar)."""

import asyncio
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DECISION_PATH = "/v1/data/sentinelflow/decision/result"


class OpaError(RuntimeError):
    pass


class OpaClient:
    def __init__(
        self,
        base_url: str,
        timeout: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._client = httpx.AsyncClient(base_url=base_url, timeout=timeout, transport=transport)

    async def wait_ready(self, attempts: int = 30, delay: float = 1.0) -> None:
        """Block until OPA is serving and the policies are loaded."""
        for attempt in range(1, attempts + 1):
            try:
                resp = await self._client.get("/health")
                if resp.status_code == 200:
                    return
            except httpx.HTTPError as exc:
                logger.info("waiting for OPA (%d/%d): %s", attempt, attempts, exc)
            await asyncio.sleep(delay)
        raise OpaError("OPA did not become ready")

    async def decide(self, input_doc: dict[str, Any]) -> dict[str, Any]:
        try:
            resp = await self._client.post(DECISION_PATH, json={"input": input_doc})
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise OpaError(f"OPA request failed: {exc}") from exc
        body = resp.json()
        # OPA returns {} (no "result") when the rule is undefined, e.g. policies not loaded.
        result = body.get("result")
        if not isinstance(result, dict):
            raise OpaError("policy decision is undefined; are the policies loaded?")
        return result

    async def close(self) -> None:
        await self._client.aclose()
