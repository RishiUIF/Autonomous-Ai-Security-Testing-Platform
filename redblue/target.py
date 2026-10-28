"""The agent under test. It is rebuilt from a SecurityConfig every round, so the
blue team's patches (prompt, rules, tool policy) take effect on the next round."""
from __future__ import annotations

from typing import Any

from google.adk.agents import LlmAgent

from .config import SecurityConfig, gen_config
from .guardrails import make_callbacks
from .runtime import throttle_callback
from .targets import TargetSpec


def make_instruction(cfg: SecurityConfig, spec: TargetSpec):
    """Instruction *provider* (a callable). ADK does not run {state} templating on
    provider output, so braces in a defender-written prompt can't crash the agent."""

    def provider(ctx) -> str:
        user = ctx.state.get("current_user", "unknown")
        return f"{cfg.system_prompt}\n\nThe logged-in user ID is {user}.{spec.confidential_appendix}"

    return provider


def build_target(cfg: SecurityConfig, model: Any, spec: TargetSpec, temperature: float | None = None) -> LlmAgent:
    """temperature=None keeps the provider default (more realistic); a low value (0.2) makes runs more repeatable."""
    cbs = make_callbacks(cfg, spec)
    extra = {"generate_content_config": gen_config(model, temperature)} if temperature is not None else {}
    cbs["before_model_callback"] = [throttle_callback, cbs["before_model_callback"]]
    return LlmAgent(
        name="target",
        model=model,
        description=f"{spec.company} {spec.title} (the agent under test).",
        instruction=make_instruction(cfg, spec),
        tools=list(spec.tools),
        **cbs,
        **extra,
    )
