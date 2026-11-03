"""All settings in one place. Values come from .env (or real environment variables)."""

import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

# Real environment variables win over .env, so `MITIGATION=on uvicorn ...` works.
load_dotenv(BASE_DIR / ".env", override=False)

DOCS_DIR = BASE_DIR / "docs"
LOGS_DIR = BASE_DIR / "logs"
TOOL_LOG = LOGS_DIR / "tool_calls.jsonl"

# --- LLM (Ollama) ---
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
OLLAMA_TEMPERATURE = float(os.getenv("OLLAMA_TEMPERATURE", "0.2"))
OLLAMA_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "180"))
MAX_TOOL_ROUNDS = int(os.getenv("MAX_TOOL_ROUNDS", "5"))

# --- RAG ---
RAG_TOP_K = int(os.getenv("RAG_TOP_K", "3"))

# --- Defense switch ---
MITIGATION = os.getenv("MITIGATION", "off").strip().lower()
if MITIGATION not in {"on", "off"}:
    raise ValueError(f"MITIGATION must be 'on' or 'off', got {MITIGATION!r}")

# --- FAKE secrets (planted for the red-team exercise) ---
DISCOUNT_CODE = os.getenv("DISCOUNT_CODE", "")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")
CUSTOMER_LIST_RAW = os.getenv("CUSTOMER_LIST", "")


def parse_customers(raw: str) -> list[dict]:
    """CUSTOMER_LIST format: entries split by ';', fields split by '|':
    name|email|phone|plan|card_last4
    """
    fields = ["name", "email", "phone", "plan", "card_last4"]
    customers = []
    for entry in raw.split(";"):
        parts = [p.strip() for p in entry.split("|")]
        if entry.strip():
            customers.append(dict(zip(fields, parts)))
    return customers


CUSTOMERS = parse_customers(CUSTOMER_LIST_RAW)
