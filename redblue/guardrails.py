"""Guardrails: ADK callbacks driven by a SecurityConfig, and the code that safely
applies the defender's proposed patches.

Three ADK hooks are used:
  before_model_callback -> scan the newest user text / tool output for injection patterns
  before_tool_callback  -> structural policy defined by the target (ownership, limits, roles, ...)
  after_model_callback  -> scan the model's reply for leaks before it reaches the user
"""
from __future__ import annotations

import json
import re
from typing import Any

from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.genai import types
from pydantic import BaseModel, Field, model_validator

from .config import Rule, SecurityConfig
from .targets import TargetSpec

MAX_PATTERN_LEN = 200
_NESTED_QUANTIFIER = re.compile(r"\([^)]*[*+][^)]*\)[*+{]")  # crude ReDoS guard, e.g. (a+)+


def _compile(rules: list[Rule]) -> list[tuple[Rule, re.Pattern]]:
    out = []
    for r in rules:
        try:
            out.append((r, re.compile(r.pattern, re.IGNORECASE | re.DOTALL)))
        except re.error:
            continue  # a bad rule must never crash the target
    return out


def _content_text(content: types.Content | None) -> str:
    """Text of a message, including serialized tool results (to catch indirect injection)."""
    if not content or not content.parts:
        return ""
    chunks = []
    for p in content.parts:
        if p.text:
            chunks.append(p.text)
        if p.function_response is not None:
            chunks.append(json.dumps(p.function_response.response, default=str))
    return "\n".join(chunks)


def make_callbacks(cfg: SecurityConfig, spec: TargetSpec) -> dict[str, Any]:
    """Build the three callbacks as closures over a (frozen-at-build-time) config."""
    input_rules = _compile(cfg.input_rules)
    output_rules = _compile(cfg.output_rules)

    def blocked() -> LlmResponse:
        return LlmResponse(content=types.Content(role="model", parts=[types.Part(text=spec.safe_reply)]))

    def before_model(callback_context, llm_request: LlmRequest):
        if not input_rules or not llm_request.contents:
            return None
        text = _content_text(llm_request.contents[-1])
        for rule, pat in input_rules:
            if pat.search(text):
                callback_context.state["last_block"] = f"input:{rule.id}"
                return blocked()
        return None

    def before_tool(tool, args: dict[str, Any], tool_context):
        msg = spec.check_tool(tool.name, args, tool_context.state, cfg.tool_rules)
        if msg:
            tool_context.state["last_block"] = f"tool:{tool.name}"
            return {"status": "blocked", "message": f"Policy: {msg}"}
        return None

    def after_model(callback_context, llm_response: LlmResponse):
        if not output_rules or not llm_response.content:
            return None
        text = _content_text(llm_response.content)
        if not text:
            return None
        for rule, pat in output_rules:
            if pat.search(text):
                callback_context.state["last_block"] = f"output:{rule.id}"
                return blocked()
        return None

    return {"before_model_callback": before_model, "before_tool_callback": before_tool,
            "after_model_callback": after_model}


# --------------------------------------------------------------------------- #
# Patches proposed by the defender, and the code that safely applies them.
# --------------------------------------------------------------------------- #
class RuleProposal(BaseModel):
    pattern: str
    description: str = ""


class ToolRulePatch(BaseModel):
    flags: dict[str, bool | None] = Field(default_factory=dict)
    limits: dict[str, float | None] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _accept_flat_form(cls, v: Any) -> Any:
        """LLMs sometimes emit {"flag": true, "limit": 5} instead of {"flags": {...}, "limits": {...}}."""
        if isinstance(v, dict) and "flags" not in v and "limits" not in v:
            flags = {k: x for k, x in v.items() if isinstance(x, bool)}
            limits = {k: x for k, x in v.items() if isinstance(x, (int, float)) and not isinstance(x, bool)}
            return {"flags": flags, "limits": limits}
        return v


class DefensePatch(BaseModel):
    analysis: str = ""
    new_system_prompt: str | None = None
    add_input_rules: list[RuleProposal] = Field(default_factory=list)
    add_output_rules: list[RuleProposal] = Field(default_factory=list)
    tool_rules: ToolRulePatch | None = None


def validate_rule(pattern: str, benign_texts: list[str]) -> str | None:
    """Return None if the regex is acceptable, otherwise the rejection reason."""
    if not pattern or len(pattern) > MAX_PATTERN_LEN:
        return f"pattern empty or longer than {MAX_PATTERN_LEN} chars"
    if _NESTED_QUANTIFIER.search(pattern):
        return "nested quantifier (possible catastrophic backtracking)"
    try:
        pat = re.compile(pattern, re.IGNORECASE | re.DOTALL)
    except re.error as e:
        return f"invalid regex: {e}"
    if pat.search(""):
        return "matches the empty string"
    for text in benign_texts:
        if pat.search(text):
            return f"would block a legitimate request: {text[:60]!r}"
    return None


def apply_patch(cfg: SecurityConfig, patch: DefensePatch, benign_texts: list[str], spec: TargetSpec) -> tuple[SecurityConfig, list[str]]:
    """Apply a patch with safety checks. Returns (new_config, log of applied/rejected changes).

    Safety properties: tool rules can only get STRICTER and only use names the target defines; every
    regex is compiled and tested against known-benign requests; the prompt is length-bounded and may
    never contain the confidential secret.
    """
    new = cfg.model_copy(deep=True)
    log: list[str] = []

    if patch.new_system_prompt:
        p = patch.new_system_prompt.strip()
        if spec.secret in p:
            log.append("REJECTED prompt: contains the confidential secret")
        elif not 80 <= len(p) <= 4000:
            log.append(f"REJECTED prompt: length {len(p)} outside 80-4000")
        else:
            new.system_prompt = p
            log.append("APPLIED new system prompt")

    for kind, proposals, target in (("input", patch.add_input_rules, new.input_rules),
                                    ("output", patch.add_output_rules, new.output_rules)):
        for prop in proposals:
            if any(r.pattern == prop.pattern for r in target):
                log.append(f"SKIPPED duplicate {kind} rule {prop.pattern!r}")
                continue
            reason = validate_rule(prop.pattern, benign_texts)
            if reason:
                log.append(f"REJECTED {kind} rule {prop.pattern!r}: {reason}")
                continue
            rule = Rule(id=f"{kind[0]}{len(target) + 1}", pattern=prop.pattern, description=prop.description)
            target.append(rule)
            log.append(f"APPLIED {kind} rule {rule.id}: {prop.pattern!r}")

    if patch.tool_rules:
        cur = new.tool_rules
        for name, val in patch.tool_rules.flags.items():
            if name not in cur.flags:
                log.append(f"REJECTED unknown tool flag {name!r}")
            elif val is True and not cur.flags[name]:
                cur.flags[name] = True
                log.append(f"APPLIED tool rule {name}=True")
            elif val is False and cur.flags[name]:
                log.append(f"REJECTED tool rule {name}=False (rules may only tighten)")
        for name, val in patch.tool_rules.limits.items():
            if val is None:
                continue
            if name not in cur.limits:
                log.append(f"REJECTED unknown tool limit {name!r}")
            elif spec.limits[name].min_value <= val < cur.limits[name]:
                cur.limits[name] = float(val)
                log.append(f"APPLIED tool rule {name}={val:g}")
            elif val >= cur.limits[name]:
                log.append(f"REJECTED tool rule {name}={val:g} (limits may only decrease)")
            else:
                log.append(f"REJECTED tool rule {name}={val:g} (below the allowed minimum {spec.limits[name].min_value:g})")

    new.version = cfg.version + 1
    new.changelog = cfg.changelog + [f"v{new.version}: " + "; ".join(log) if log else f"v{new.version}: no changes"]
    return new, log
