#!/usr/bin/env python3
from __future__ import annotations

import inspect
import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

try:
    from mcp import ClientSession
except ImportError:
    from mcp.client.session import ClientSession  # type: ignore

try:
    from mcp.client.streamable_http import streamablehttp_client
except ImportError:
    from mcp.client.streamable_http import streamable_http_client as streamablehttp_client  # type: ignore


def model_to_dict(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(by_alias=True)
    if hasattr(value, "dict"):
        return value.dict(by_alias=True)
    return value


def parse_tool_result(result: Any) -> dict[str, Any]:
    raw = model_to_dict(result)
    if isinstance(raw, dict):
        is_error = bool(raw.get("isError", raw.get("is_error", False)))
        structured = raw.get("structuredContent", raw.get("structured_content"))
        content = raw.get("content", [])
    else:
        is_error = bool(getattr(result, "isError", getattr(result, "is_error", False)))
        structured = getattr(result, "structuredContent", getattr(result, "structured_content", None))
        content = getattr(result, "content", [])
    if isinstance(structured, dict):
        if is_error:
            raise RuntimeError(json.dumps(structured, sort_keys=True))
        return structured
    text_parts: list[str] = []
    for item in content or []:
        row = model_to_dict(item)
        if isinstance(row, dict) and isinstance(row.get("text"), str):
            text_parts.append(row["text"])
        elif isinstance(getattr(item, "text", None), str):
            text_parts.append(item.text)
    text = "\n".join(text_parts).strip()
    if is_error:
        raise RuntimeError(text or "MCP tool returned isError")
    if text:
        try:
            decoded = json.loads(text)
            if isinstance(decoded, dict):
                return decoded
        except json.JSONDecodeError:
            return {"text": text}
    return {}


async def call(session: ClientSession, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return parse_tool_result(await session.call_tool(name, arguments))


async def expect_error(session: ClientSession, name: str, arguments: dict[str, Any], contains: str | None = None) -> bool:
    try:
        await call(session, name, arguments)
    except Exception as exc:
        return contains is None or contains in str(exc)
    return False


def endpoint(port: int, token: str | None = None) -> tuple[str, dict[str, str]]:
    root = Path.home() / "ledgerforge-mcp-prototype"
    token_path = root / ".executor-token"
    path_file = root / ".executor-path"
    if not path_file.is_file() and (root / ".mcp-path").is_file():
        path_file = root / ".mcp-path"
    if not token_path.is_file() or not path_file.is_file():
        raise RuntimeError("Persisted MCP identity is missing.")
    if token is None:
        token = token_path.read_text(encoding="utf-8").strip()
    path = path_file.read_text(encoding="utf-8").strip()
    if not token or not path:
        raise RuntimeError("Persisted MCP identity is empty.")
    return f"http://127.0.0.1:{port}{path}", {"Authorization": f"Bearer {token}"}


@asynccontextmanager
async def open_session(port: int, token: str | None = None) -> AsyncIterator[ClientSession]:
    """Open an authenticated local session; an explicit token is never logged."""
    url, headers = endpoint(port, token)
    parameters = inspect.signature(streamablehttp_client).parameters
    if "headers" in parameters:
        kwargs = {"headers": headers}
        if "timeout" in parameters:
            kwargs["timeout"] = 900.0
        async with streamablehttp_client(url, **kwargs) as streams:
            async with ClientSession(streams[0], streams[1]) as session:
                await session.initialize()
                yield session
        return
    if "http_client" in parameters:
        try:
            import httpx2 as httpx_client_module  # type: ignore
        except ImportError:
            import httpx as httpx_client_module  # type: ignore
        async with httpx_client_module.AsyncClient(headers=headers, follow_redirects=True, timeout=900.0) as client:
            async with streamablehttp_client(url, http_client=client) as streams:
                async with ClientSession(streams[0], streams[1]) as session:
                    await session.initialize()
                    yield session
        return
    raise RuntimeError("Installed MCP client exposes no supported authenticated streamable HTTP mode.")
