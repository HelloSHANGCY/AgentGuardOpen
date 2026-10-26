from dataclasses import dataclass
from typing import Callable

from fastapi import FastAPI, Request


@dataclass
class Tool:
    name: str
    description: str
    schema: dict
    handler: Callable
    hidden: bool = False


def create_server(name: str, tools: list[Tool], on_start: Callable | None = None) -> FastAPI:
    registry = {tool.name: tool for tool in tools}
    app = FastAPI(title=f"mcp-{name}")

    @app.on_event("startup")
    def startup_handler():
        if on_start:
            on_start()

    @app.post("/mcp")
    async def mcp(request: Request):
        req = await request.json()
        method = req.get("method")
        if method == "tools/list":
            result = {"tools": [{"name": t.name} for t in tools if not t.hidden]}
        elif method == "tools/call":
            tool = registry.get(req.get("params", {}).get("name"))
            result = tool.handler(**req.get("params", {}).get("arguments", {})) if tool else {}
        else:
            result = {}
        return {"result": result}

    return app
