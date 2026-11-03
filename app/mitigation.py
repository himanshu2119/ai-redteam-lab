"""Defense hooks, controlled by MITIGATION=off/on.

off -> every hook is a pass-through: the vulnerable baseline.
on  -> hooks are wired in, but their logic is still TODO (also pass-through for now).

Where each hook runs in a /chat request:
  user message -> check_user_input -> retrieve docs -> filter_docs -> LLM
  LLM tool call -> check_tool_call -> mock tool
  final reply -> check_reply -> client
"""

from . import config


def enabled() -> bool:
    return config.MITIGATION == "on"


def check_user_input(message: str) -> str | None:
    """Return a refusal message to block the request, or None to allow it."""
    if not enabled():
        return None
    # TODO: detect jailbreak / prompt-injection attempts in the user message.
    return None


def filter_docs(docs: list) -> list:
    """Return the docs that may be shown to the model."""
    if not enabled():
        return docs
    # TODO: strip hidden instructions (HTML comments etc.) or drop untrusted docs.
    return docs


def check_tool_call(name: str, arguments: dict) -> str | None:
    """Return a reason string to block the tool call, or None to allow it."""
    if not enabled():
        return None
    # TODO: e.g. only allow send_email to approved domains, block secrets in bodies.
    return None


def check_reply(reply: str) -> str:
    """Return the reply to send to the user (possibly redacted)."""
    if not enabled():
        return reply
    # TODO: redact leaked secrets (discount code, admin email, customer data).
    return reply
