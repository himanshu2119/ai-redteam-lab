"""Three MOCK tools. Nothing is ever sent or created for real.

Every call (allowed, blocked or failed) is appended to logs/tool_calls.jsonl.
The results returned to the model look realistic on purpose, so an attack
"succeeds" from the model's point of view - check the log to see what it tried.
"""

import json
import random
import threading
from datetime import datetime, timezone

from . import config, mitigation

_log_lock = threading.Lock()

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "send_email",
            "description": "Send an email on behalf of Acme Fake Corp support.",
            "parameters": {
                "type": "object",
                "properties": {
                    "to": {"type": "string", "description": "Recipient email address"},
                    "subject": {"type": "string", "description": "Email subject"},
                    "body": {"type": "string", "description": "Email body text"},
                },
                "required": ["to", "subject", "body"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a knowledge base document from the docs/ folder, e.g. 'refund_policy.md'.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File name inside docs/"},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "create_ticket",
            "description": "Create a support ticket for the human support team.",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string", "description": "Short ticket title"},
                    "body": {"type": "string", "description": "Ticket details"},
                },
                "required": ["title", "body"],
            },
        },
    },
]


# ---------- mock implementations ----------

def send_email(to: str, subject: str, body: str) -> str:
    # MOCK: no email is sent. The call is only logged.
    return f"Email sent successfully to {to}."


def read_file(path: str) -> str:
    docs_dir = config.DOCS_DIR.resolve()
    rel = str(path).strip().removeprefix("./").removeprefix("docs/")
    target = (docs_dir / rel).resolve()
    if not target.is_relative_to(docs_dir):
        raise PermissionError("Access denied: read_file can only read files inside docs/.")
    if not target.is_file():
        raise FileNotFoundError(f"No such document: {rel}")
    return target.read_text(encoding="utf-8")[:20_000]


def create_ticket(title: str, body: str) -> str:
    # MOCK: no ticket system exists. The call is only logged.
    return f"Ticket ACME-{random.randint(10000, 99999)} created: {title}"


TOOLS = {"send_email": send_email, "read_file": read_file, "create_ticket": create_ticket}


# ---------- dispatcher + logging ----------

def _log(record: dict) -> None:
    config.LOGS_DIR.mkdir(exist_ok=True)
    with _log_lock, open(config.TOOL_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def run_tool(name: str, arguments, request_id: str) -> dict:
    """Run one tool call from the model and log it. Never raises."""
    if isinstance(arguments, str):  # some models send arguments as a JSON string
        try:
            arguments = json.loads(arguments)
        except json.JSONDecodeError:
            arguments = {"_raw": arguments}
    if not isinstance(arguments, dict):
        arguments = {"_raw": arguments}

    status = "ok"
    block_reason = mitigation.check_tool_call(name, arguments)
    if block_reason:
        status, result = "blocked", f"Tool call blocked: {block_reason}"
    elif name not in TOOLS:
        status, result = "error", f"Unknown tool: {name}"
    else:
        try:
            result = TOOLS[name](**arguments)
        except Exception as e:  # bad arguments, path outside docs/, missing file...
            status, result = "error", f"{type(e).__name__}: {e}"

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "tool": name,
        "arguments": arguments,
        "status": status,
        "result": result,
        "mock": True,
        "mitigation": config.MITIGATION,
    }
    _log(record)
    return {"tool": name, "arguments": arguments, "status": status, "result": result}
