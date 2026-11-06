"""FastAPI app: POST /chat runs one bot turn (RAG -> LLM -> tools -> reply)."""

import logging
import uuid
from typing import Literal

from fastapi import FastAPI, HTTPException, Response
from pydantic import BaseModel, Field

from . import config, llm, mitigation, rag, tools
from .prompts import build_system_prompt

log = logging.getLogger("uvicorn.error")

app = FastAPI(
    title="Acme Fake Corp HelpDesk Bot",
    description="Deliberately vulnerable red-team lab target. All data is fake; all tools are mocks.",
)


class Turn(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class ChatRequest(BaseModel):
    message: str = Field(min_length=1)
    history: list[Turn] = []


class ToolCall(BaseModel):
    tool: str
    arguments: dict
    status: str
    result: str


class ChatResponse(BaseModel):
    request_id: str
    reply: str
    tool_calls: list[ToolCall]
    retrieved_docs: list[str]
    mitigation: str


@app.get("/health")
def health():
    return {"status": "ok", "model": config.OLLAMA_MODEL, "mitigation": config.MITIGATION}


@app.post("/chat", response_model=ChatResponse)
def chat(req: ChatRequest, response: Response):
    request_id = uuid.uuid4().hex
    response.headers["X-Request-ID"] = request_id

    def done(reply: str, tool_calls: list, docs: list) -> ChatResponse:
        return ChatResponse(
            request_id=request_id,
            reply=reply,
            tool_calls=tool_calls,
            retrieved_docs=[d.name for d in docs],
            mitigation=config.MITIGATION,
        )

    refusal = mitigation.check_user_input(req.message)
    if refusal:
        return done(refusal, [], [])

    docs = mitigation.filter_docs(rag.retrieve(req.message))
    messages = [{"role": "system", "content": build_system_prompt(docs)}]
    messages += [t.model_dump() for t in req.history]
    messages.append({"role": "user", "content": req.message})

    tool_calls: list[dict] = []
    reply = "(no reply: the bot kept calling tools and hit MAX_TOOL_ROUNDS)"
    for _ in range(config.MAX_TOOL_ROUNDS):
        try:
            msg = llm.chat(messages, tools.TOOL_SCHEMAS)
        except llm.LLMError as e:
            raise HTTPException(status_code=502, detail=str(e))

        calls = msg.get("tool_calls") or []
        if not calls:
            reply = msg.get("content", "")
            break

        messages.append({"role": "assistant", "content": msg.get("content", ""), "tool_calls": calls})
        for call in calls:
            fn = call.get("function", {})
            result = tools.run_tool(fn.get("name", ""), fn.get("arguments", {}), request_id)
            log.info("[%s] tool %s(%s) -> %s", request_id[:8], result["tool"], result["arguments"], result["status"])
            tool_calls.append(result)
            messages.append({"role": "tool", "content": result["result"], "tool_name": result["tool"]})

    return done(mitigation.check_reply(reply, request_id), tool_calls, docs)
