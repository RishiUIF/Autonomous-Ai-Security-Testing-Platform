"""Per-role models, local-model throttling bypass, and the capability pre-flight (no network)."""
import asyncio
from types import SimpleNamespace

import pytest

from redblue import preflight
from redblue.config import Settings, provider_of
from redblue.runtime import set_rpm, throttle_callback


def test_role_models_and_summary():
    s = Settings(model="gemini-3.6-flash", target_model="ollama_chat/llama3.1:8b", defender_model=None, attacker_model=None)
    assert s.name_for("target") == "ollama_chat/llama3.1:8b"
    assert s.name_for("attacker") == s.name_for("judge") == s.name_for("defender") == "gemini-3.6-flash"
    assert "target=ollama_chat/llama3.1:8b" in s.model_summary()
    assert Settings(model="gemini-3.6-flash", target_model=None, attacker_model=None, defender_model=None).model_summary() == "gemini-3.6-flash"
    assert provider_of("ollama_chat/x").startswith("ollama")


def test_local_models_are_never_throttled():
    set_rpm(1)  # one request per minute: a throttled second call would block ~60s
    try:
        async def go():
            for m in ("ollama_chat/llama3.1:8b", "ollama_chat/llama3.1:8b", "ollama/qwen2.5:7b"):
                await asyncio.wait_for(throttle_callback(None, SimpleNamespace(model=m)), timeout=1)
        asyncio.run(go())
    finally:
        set_rpm(0)


def test_preflight_warns_when_model_cannot_call_tools(monkeypatch, capsys):
    pytest.importorskip("litellm")
    from google.adk.models.lite_llm import LiteLlm

    monkeypatch.setattr(preflight, "resolve_model", lambda name: LiteLlm(model="ollama_chat/fake", mock_response="OK"))
    assert asyncio.run(preflight.check_model("ollama_chat/fake", ["target"])) is True
    out = capsys.readouterr().out
    assert "did not call a simple tool" in out
    assert asyncio.run(preflight.check_model("ollama_chat/fake", ["attacker"])) is True
    assert "did not return clean JSON" in capsys.readouterr().out


def test_judge_model_and_temperature_options():
    s = Settings(model="m", judge_model="ollama_chat/j", target_temperature=0.2, target_model=None, attacker_model=None, defender_model=None)
    assert s.name_for("judge") == "ollama_chat/j" and s.name_for("reporter") == "m"
    from redblue.config import SecurityConfig
    from redblue.target import build_target
    from redblue.targets import get_target
    spec = get_target("shopco")
    agent = build_target(SecurityConfig.baseline(spec), "gemini-3.6-flash", spec, 0.2)
    assert agent.generate_content_config.temperature == 0.2
    assert build_target(SecurityConfig.baseline(spec), "gemini-3.6-flash", spec).generate_content_config is None


def test_defender_hints_cover_the_failure_seen_with_small_models():
    from redblue.blue_team import hints_for
    h = hints_for([{"verdict": {"category": "secret_leak"}}, {"verdict": {"category": "unauthorized_refund"}}])
    assert any("OUTPUT rule" in x for x in h) and any("structural" in x for x in h)
    assert hints_for([]) == []
