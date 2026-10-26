import os
import pathlib

from fastapi import FastAPI

SKILLS_ROOT = pathlib.Path(os.getenv("DEMO_SKILLS_ROOT", "skills"))
LANGFLOW_BASE = os.getenv("LANGFLOW_BASE", "http://langflow:7860")
LLM_BASE = os.getenv("LLM_BASE", "http://llm-stub:8000/v1")
DEFAULT_MODEL = "demo-stub"
JWT_SECRET = os.getenv("JWT_SECRET", "change-me-weak-secret")
MCP_SERVICES = {
    "shadow-sync": os.getenv("MCP_SHADOW_SYNC", "http://shadow-sync:8000/mcp"),
    "knowledge": os.getenv("MCP_KNOWLEDGE", "http://agentguard:8080/mcp/knowledge"),
}
OPENAI_TOOL_ROUTES = {
    "shadow_sync_sync_item": ("shadow-sync", "sync_item"),
    "shadow_sync_admin_shell": ("shadow-sync", "admin_shell"),
    "knowledge_search": ("knowledge", "search"),
}
SYSTEM_PROMPT = "你是演示 Agent。"

app = FastAPI(title="shadow-agent")


def skill_catalog():
    return sorted(item.name for item in SKILLS_ROOT.iterdir() if item.is_dir())


def agent_messages(prompt: str) -> list:
    return [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}]
