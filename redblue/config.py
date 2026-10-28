"""Settings, the mutable SecurityConfig that the blue team hardens, and model resolution."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from google.genai import types
from pydantic import BaseModel, Field

from .targets import TargetSpec, get_target
from .targets.base import GUARDRAIL_MARKER  # noqa: F401  (re-exported)

ROOT = Path(__file__).resolve().parent.parent

# Model names with these prefixes are routed through LiteLLM (AWS Bedrock, Ollama, OpenAI, ...).
LITELLM_PREFIXES = ("bedrock/", "ollama/", "ollama_chat/", "openai/", "anthropic/", "azure/", "groq/", "mistral/",
                    "together_ai/", "deepseek/", "openrouter/", "xai/", "cohere/", "fireworks_ai/", "sagemaker/", "huggingface/")


def resolve_model(name: str) -> Any:
    """'gemini-...' stays a plain string (native ADK); 'bedrock/...' etc. become a LiteLlm wrapper."""
    if name.lower().startswith(LITELLM_PREFIXES):
        import litellm
        from google.adk.models.lite_llm import LiteLlm

        litellm.suppress_debug_info = True
        if name.lower().startswith(("ollama/", "ollama_chat/")):
            # Ollama's default context window is small and silently truncates long prompts.
            return LiteLlm(model=name, num_ctx=int(os.getenv("REDBLUE_OLLAMA_NUM_CTX", "8192")))
        return LiteLlm(model=name)
    return name


def provider_of(name: str) -> str:
    low = name.lower()
    for p in LITELLM_PREFIXES:
        if low.startswith(p):
            return p.rstrip("/")
    return "gemini"


def gen_config(model: Any, temperature: float, as_json: bool = False) -> types.GenerateContentConfig:
    """Only Gemini (and the offline demo model) understand response_mime_type; others get plain text
    and rely on the tolerant JSON extractor."""
    native = not isinstance(model, str) or model.lower().startswith("gemini")
    kw: dict[str, Any] = {"temperature": temperature}
    if as_json and native:
        kw["response_mime_type"] = "application/json"
    return types.GenerateContentConfig(**kw)


class ToolRules(BaseModel):
    """Structural guardrails enforced in before_tool_callback. Names are defined by the target."""

    flags: dict[str, bool] = Field(default_factory=dict)
    limits: dict[str, float] = Field(default_factory=dict)


class Rule(BaseModel):
    id: str
    pattern: str
    description: str = ""


class SecurityConfig(BaseModel):
    target: str = "shopco"
    version: int = 0
    system_prompt: str = ""
    input_rules: list[Rule] = Field(default_factory=list)  # checked in before_model_callback
    output_rules: list[Rule] = Field(default_factory=list)  # checked in after_model_callback
    tool_rules: ToolRules = Field(default_factory=ToolRules)
    changelog: list[str] = Field(default_factory=list)

    @classmethod
    def baseline(cls, spec: TargetSpec) -> "SecurityConfig":
        """The deliberately weak 'before' picture for a target."""
        return cls(target=spec.id, system_prompt=spec.weak_prompt,
                   tool_rules=ToolRules(flags={k: False for k in spec.flags},
                                        limits={k: v.default for k, v in spec.limits.items()}))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.model_dump_json(indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "SecurityConfig":
        return cls.model_validate_json(Path(path).read_text(encoding="utf-8"))


class Settings(BaseModel):
    demo: bool = False  # offline simulation with scripted fake LLMs, no API key needed
    target: str = "shopco"
    model: str = Field(default_factory=lambda: os.getenv("REDBLUE_MODEL", "gemini-3.6-flash"))
    defender_model: str | None = Field(default_factory=lambda: os.getenv("REDBLUE_DEFENDER_MODEL") or None)
    judge_model: str | None = Field(default_factory=lambda: os.getenv("REDBLUE_JUDGE_MODEL") or None)
    target_temperature: float | None = Field(
        default_factory=lambda: float(os.getenv("REDBLUE_TARGET_TEMPERATURE")) if os.getenv("REDBLUE_TARGET_TEMPERATURE") else None)
    target_model: str | None = Field(default_factory=lambda: os.getenv("REDBLUE_TARGET_MODEL") or None)
    attacker_model: str | None = Field(default_factory=lambda: os.getenv("REDBLUE_ATTACKER_MODEL") or None)
    defender_max_breaches: int = 10  # breaches shown to the defender per round (lower for small local models)
    max_rounds: int = 4
    attacks_per_category: int = 2
    corpus_replay_cap: int = 10
    concurrency: int = 3
    use_llm_judge: bool = True
    out_dir: Path = ROOT / "outputs"

    @property
    def spec(self) -> TargetSpec:
        return get_target(self.target)

    def name_for(self, role: str) -> str:
        """Model name for a role: target / attacker / defender / judge can be overridden; the reporter uses `model`."""
        override = {"target": self.target_model, "attacker": self.attacker_model, "defender": self.defender_model,
                    "judge": self.judge_model}.get(role)
        return override or self.model

    def model_names(self) -> dict[str, str]:
        return {r: self.name_for(r) for r in ("target", "attacker", "defender", "judge", "reporter")}

    def model_summary(self) -> str:
        names = self.model_names()
        if len(set(names.values())) == 1:
            return self.model
        return ", ".join(f"{r}={n}" for r, n in names.items() if r != "reporter")

    def model_for(self, role: str) -> Any:
        """Return a model string / LiteLlm wrapper, or a scripted fake model in demo mode."""
        if self.demo:
            from .demo_llm import DemoLLM

            return DemoLLM(model=f"demo-{role}", role=role, target_id=self.target)
        return resolve_model(self.name_for(role))


def load_json(target_id: str, name: str) -> Any:
    return json.loads((ROOT / "attacks" / target_id / name).read_text(encoding="utf-8"))
