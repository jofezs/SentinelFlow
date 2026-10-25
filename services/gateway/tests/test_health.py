import httpx


async def test_liveness(client: httpx.AsyncClient) -> None:
    resp = await client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


async def test_readiness_checks_database(client: httpx.AsyncClient) -> None:
    resp = await client.get("/readyz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready"}


async def test_openapi_schema_is_served(client: httpx.AsyncClient) -> None:
    resp = await client.get("/openapi.json")
    assert resp.status_code == 200
    assert "/v1/scans" in resp.json()["paths"]
