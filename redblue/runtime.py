"""Thin wrappers around the ADK Runner: run a scripted conversation against an
agent and capture replies + tool calls, or run an agent that must return JSON."""
from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from typing import Any, TypeVar

from google.adk.agents import BaseAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from pydantic import BaseModel, ValidationError


logging.getLogger("google_adk").setLevel(logging.CRITICAL)  # we handle/report errors ourselves; hide ADK tracebacks

MAX_WAIT_S = 180  # longest single wait we accept before giving up
RETRYABLE = ("429", "RESOURCE_EXHAUSTED", "503", "UNAVAILABLE", "500", "INTERNAL", "DEADLINE", "timed out",
             "ThrottlingException", "RateLimitError", "Too many requests", "ServiceUnavailable", "Timeout", "ConnectionError")


class RateLimiter:
    """Spaces LLM calls so we stay under a requests-per-minute quota (0 = off)."""

    def __init__(self, rpm: float = 0):
        self.interval = 60.0 / rpm if rpm else 0.0
        self._next = 0.0

    async def wait(self) -> None:
        if not self.interval:
            return
        now = time.monotonic()
        start = max(now, self._next)  # no await between read and write, so this is race-free
        self._next = start + self.interval
        if start > now:
            await asyncio.sleep(start - now)


LIMITER = RateLimiter(0)


def set_rpm(rpm: float) -> None:
    global LIMITER
    LIMITER = RateLimiter(rpm)


async def throttle_callback(callback_context, llm_request):
    """before_model_callback attached to every agent: wait for a free request slot.
    Local Ollama models have no request quota, so they are never throttled."""
    if str(getattr(llm_request, "model", "") or "").lower().startswith(("ollama/", "ollama_chat/")):
        return None
    await LIMITER.wait()
    return None


def _retry_delay(err: str, attempt: int) -> float:
    m = re.search(r"retry in ([\d.]+)s", err, re.IGNORECASE) or re.search(r"retryDelay'?\W+(\d+)s", err)
    return float(m.group(1)) + 2 if m else min(2 ** attempt * 2, 30)


class ToolCall(BaseModel):
    turn: int
    name: str
    args: dict[str, Any]
    response: dict[str, Any] | None = None


class Transcript(BaseModel):
    turns: list[str]
    replies: list[str] = []
    tool_calls: list[ToolCall] = []
    error: str | None = None

    @property
    def all_replies(self) -> str:
        return "\n".join(self.replies)


def log(msg: str) -> None:
    print(msg, flush=True)


async def _run_once(agent: BaseAgent, turns: list[str], state: dict[str, Any], app_name: str) -> Transcript:
    svc = InMemorySessionService()
    runner = Runner(agent=agent, app_name=app_name, session_service=svc)
    sid, uid = uuid.uuid4().hex, "redteam"
    await svc.create_session(app_name=app_name, user_id=uid, session_id=sid, state=dict(state))
    tr = Transcript(turns=list(turns))

    for i, text in enumerate(turns):
        msg = types.Content(role="user", parts=[types.Part(text=text)])
        reply_parts: list[str] = []
        pending: list[ToolCall] = []
        async for event in runner.run_async(user_id=uid, session_id=sid, new_message=msg):
            if not event.content or not event.content.parts:
                continue
            for part in event.content.parts:
                if part.function_call:
                    tc = ToolCall(turn=i, name=part.function_call.name, args=dict(part.function_call.args or {}))
                    pending.append(tc)
                    tr.tool_calls.append(tc)
                elif part.function_response:
                    for tc in pending:  # match the oldest unanswered call with the same name
                        if tc.name == part.function_response.name and tc.response is None:
                            tc.response = dict(part.function_response.response or {})
                            break
            if event.is_final_response():
                reply_parts += [p.text for p in event.content.parts if p.text and not getattr(p, "thought", False)]
        tr.replies.append("\n".join(reply_parts).strip())
    return tr


async def run_conversation(
    agent: BaseAgent, turns: list[str], state: dict[str, Any] | None = None,
    app_name: str = "redblue_meta", retries: int = 6,
) -> Transcript:
    """Run the turns in one fresh session. Retries transient API errors with backoff.
    Never raises: failures come back as Transcript.error so one bad call can't kill a run."""
    state = state or {}
    last_err = ""
    for attempt in range(retries + 1):
        try:
            return await _run_once(agent, turns, state, app_name)
        except Exception as e:  # noqa: BLE001
            last_err = f"{type(e).__name__}: {e}"
            if attempt < retries and any(tok in last_err for tok in RETRYABLE):
                delay = _retry_delay(last_err, attempt)
                if delay > MAX_WAIT_S:  # e.g. a DAILY quota: waiting hours silently is never what the user wants
                    last_err = (f"Quota exhausted; the API says to retry in {delay / 3600:.1f} hours (likely the daily limit). "
                                "Use a different model (--model), enable billing, or try again after the quota resets.")
                    break
                log(f"    rate limited / transient API error, retrying in {delay:.0f}s (attempt {attempt + 1}/{retries})")
                await asyncio.sleep(delay)
                continue
            break
    log(f"    API error: {last_err[:300]}")
    return Transcript(turns=list(turns), error=last_err[:500])


# ---- JSON-returning agents (attackers, judge, defender, reporter) ------------- #
M = TypeVar("M", bound=BaseModel)


def extract_json(text: str) -> Any:
    """Parse JSON from model output, tolerating code fences and surrounding prose."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.IGNORECASE)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = min([i for i in (text.find("{"), text.find("[")) if i != -1], default=-1)
    if start == -1:
        raise ValueError("no JSON found")
    end = max(text.rfind("}"), text.rfind("]"))
    return json.loads(text[start : end + 1])


async def run_json_agent(agent: BaseAgent, payload: dict[str, Any] | str, schema: type[M], attempts: int = 2) -> M | None:
    """Send `payload` to an agent and validate its reply against a pydantic schema."""
    prompt = payload if isinstance(payload, str) else json.dumps(payload, indent=2, default=str)
    for _ in range(attempts):
        tr = await run_conversation(agent, [prompt], app_name="redblue_meta")
        if tr.error:
            log(f"  [{agent.name}] failed: {tr.error[:300]}")
            continue
        if not tr.replies or not tr.replies[0]:
            log(f"  [{agent.name}] returned an empty reply (possibly a safety refusal); retrying")
            continue
        try:
            return schema.model_validate(extract_json(tr.replies[0]))
        except (ValueError, ValidationError):
            log(f"  [{agent.name}] reply was not valid JSON: {tr.replies[0][:150]!r}")
            prompt += "\n\nYour previous reply was not valid JSON for the required schema. Reply with ONLY the JSON."
    return None
