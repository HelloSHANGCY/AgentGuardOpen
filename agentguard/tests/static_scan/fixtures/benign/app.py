import os
import pathlib

from fastapi import FastAPI

from skills.loader import load_skill

SKILLS_ROOT = pathlib.Path(os.getenv("DEMO_SKILLS_ROOT", "skills"))
LLM_BASE = os.getenv("LLM_BASE", "http://llm-gateway:8000/v1")
DEFAULT_MODEL = "demo-model"
MCP_SERVICES = {
    "safe-sync": os.getenv("MCP_SAFE_SYNC", "http://agentguard:8080/mcp/safe-sync"),
}
SYSTEM_PROMPT = "你是演示 Agent。"
JWT_SECRET = os.getenv("JWT_SECRET", "demo-strong-secret-value-2026")

app = FastAPI(title="demo-agent")


def skill_catalog():
    return [load_skill(str(item)) for item in SKILLS_ROOT.iterdir() if item.is_dir()]


def agent_messages(prompt: str) -> list:
    return [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}]
