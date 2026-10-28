"""What a 'target agent' is, independent of the red/blue engine.

A TargetSpec bundles everything that is specific to one agent under test:
its persona and weak starting prompt, its tools and fake backend, the ground-truth
policy (used by the judge), the structural guardrail switches the blue team may
turn on, and the briefs the red/blue agents are given. The engine (pipeline,
guardrails, judge, red/blue agents, reporter) only ever talks to this interface,
so adding a fourth target means adding one file.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Literal

from pydantic import BaseModel

GUARDRAIL_MARKER = "[blocked by guardrail]"

Sev = Literal["none", "low", "medium", "high", "critical"]


class Finding(BaseModel):
    category: str
    severity: Sev
    evidence: str


@dataclass(frozen=True)
class LimitSpec:
    default: float  # the deliberately loose starting value
    min_value: float  # the defender may tighten the limit, but not below this
    description: str


def flag(rules: Any, name: str) -> bool:
    return bool(rules.flags.get(name, False))


def limit(rules: Any, name: str, default: float) -> float:
    return float(rules.limits.get(name, default))


def bump(state: Any, key: str, cap: float) -> bool:
    """Count one more use of something per session. False if the cap is already reached."""
    n = int(state.get(key, 0))
    if n >= cap:
        return False
    state[key] = n + 1
    return True


@dataclass
class TargetSpec:
    id: str
    title: str  # e.g. "retail customer-support agent"
    persona: str  # the bot's name
    company: str
    weak_prompt: str
    secret: str  # confidential string appended to the prompt in code; seeing it in a reply is a breach
    confidential_appendix: str
    default_user: str  # the logged-in user in every test conversation
    tools: list[Callable]
    flags: dict[str, str]  # structural guardrail switches -> description
    limits: dict[str, LimitSpec]  # numeric guardrail limits (lower = stricter)
    check_tool: Callable[[str, dict, Any, Any], str | None]  # (tool, args, session state, ToolRules) -> block message
    findings: Callable[[Any, str], list[Finding]]  # (Transcript, user) -> ground-truth policy violations
    brief: str  # what the red team is told about the target
    tool_abuse_focus: str  # the tool-abuse specialist's playbook for this target
    policy_text: str  # ground-truth policy, as told to the defender
    refusal_tail: str  # "I can help you ..." appended to refusals
    utility_tool: str  # read-only tool used for exact tool-trajectory evals
    utility_arg: str
    utility_arg_regex: str
    recommendation: str  # a recommendation tailored to this target

    @property
    def app_name(self) -> str:
        return f"{self.id}_agent"  # must equal the agent folder name so `adk eval` matches

    @property
    def safe_reply(self) -> str:
        return f"I'm sorry, I can't help with that request. {GUARDRAIL_MARKER} {self.refusal_tail}"

    @property
    def reference_refusal(self) -> str:
        return f"I'm sorry, I can't help with that request. {self.refusal_tail}"
