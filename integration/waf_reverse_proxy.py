"""
Lightweight reverse proxy that enforces the WAF without modifying the Flask app.
Run this proxy in front of the Flask dev server and browse the proxy port.
"""

import os
import logging
from typing import Dict
from contextlib import asynccontextmanager

import aiohttp
import uvicorn
from fastapi import FastAPI, Request, Response


LOGGER = logging.getLogger("waf_reverse_proxy")

UPSTREAM_URL = os.getenv("WAF_PROXY_UPSTREAM", "http://127.0.0.1:5000")
WAF_URL = os.getenv("WAF_PROXY_WAF_URL", "http://127.0.0.1:8000/scan")
PROXY_HOST = os.getenv("WAF_PROXY_HOST", "127.0.0.1")
PROXY_PORT = int(os.getenv("WAF_PROXY_PORT", "8080"))
WAF_TIMEOUT = float(os.getenv("WAF_PROXY_WAF_TIMEOUT", "2.0"))
UPSTREAM_TIMEOUT = float(os.getenv("WAF_PROXY_UPSTREAM_TIMEOUT", "10.0"))
FAIL_OPEN = os.getenv("WAF_PROXY_FAIL_OPEN", "true").lower() == "true"
BLOCK_ON_ANOMALY = os.getenv("WAF_PROXY_BLOCK_ON_ANOMALY", "true").lower() == "true"

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    logging.basicConfig(level=logging.INFO)
    app.state.session = aiohttp.ClientSession()
    LOGGER.info(
        "Proxy started",
        extra={"upstream": UPSTREAM_URL, "waf": WAF_URL},
    )
    yield
    await app.state.session.close()


app = FastAPI(lifespan=lifespan)


def _filter_headers(headers: Dict[str, str]) -> Dict[str, str]:
    return {
        k: v
        for k, v in headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    }


async def _call_waf(request: Request, body_text: str) -> Response | None:
    payload = {
        "method": request.method,
        "path": request.url.path or "/",
        "query_string": request.url.query or "",
        "headers": dict(request.headers),
        "body": body_text,
    }

    try:
        async with app.state.session.post(
            WAF_URL,
            json=payload,
            timeout=WAF_TIMEOUT,
        ) as waf_resp:
            if waf_resp.status == 403:
                return Response(status_code=403)

            if waf_resp.status == 200 and BLOCK_ON_ANOMALY:
                data = await waf_resp.json()
                if data.get("is_anomalous"):
                    return Response(status_code=403)

    except Exception as exc:
        LOGGER.warning("WAF request failed: %s", exc)
        if not FAIL_OPEN:
            return Response(status_code=503)

    return None


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
async def proxy(request: Request, path: str):
    body_bytes = await request.body()
    body_text = body_bytes.decode("utf-8", errors="ignore")

    waf_response = await _call_waf(request, body_text)
    if waf_response is not None:
        return waf_response

    upstream_url = f"{UPSTREAM_URL}{request.url.path}"
    if request.url.query:
        upstream_url = f"{upstream_url}?{request.url.query}"

    headers = _filter_headers(dict(request.headers))

    async with app.state.session.request(
        request.method,
        upstream_url,
        headers=headers,
        data=body_bytes,
        allow_redirects=False,
        timeout=UPSTREAM_TIMEOUT,
    ) as upstream_resp:
        resp_body = await upstream_resp.read()
        resp_headers = _filter_headers(dict(upstream_resp.headers))

        return Response(
            content=resp_body,
            status_code=upstream_resp.status,
            headers=resp_headers,
        )


if __name__ == "__main__":
    uvicorn.run(app, host=PROXY_HOST, port=PROXY_PORT)
