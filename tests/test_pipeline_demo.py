"""End-to-end test of the whole loop, for every target, using the scripted offline models."""
import asyncio

import pytest
from google.adk.evaluation.eval_set import EvalSet

from redblue.config import SecurityConfig, Settings, resolve_model
from redblue.pipeline import run_pipeline, run_regression, save_run
from redblue.reporter import build_summary, render_combined_markdown, render_markdown
from redblue.runtime import run_conversation
from redblue.target import build_target
from redblue.targets import TARGETS, get_target


@pytest.mark.parametrize("target", list(TARGETS))
def test_full_demo_loop(tmp_path, target):
    s = Settings(demo=True, target=target, out_dir=tmp_path)
    result, corpus = asyncio.run(run_pipeline(s, "batch"))
    first, last = result.rounds[0], result.rounds[-1]
    assert first.train_breaches > 0 and first.holdout_breaches > 0  # the weak baseline really is breakable
    assert last.train_breaches == 0 and last.holdout_breaches == 0 and result.converged
    assert last.utility == 1.0  # hardening didn't break legitimate use
    assert not [e for e in result.attack_log if e["status"] == "unresolved"]  # every old breach re-verified against the final config
    assert any(e["status"] == "fixed" for e in result.attack_log)
    assert result.final_config.version >= 1 and result.final_config.target == target

    out = save_run(result, s, render_markdown(result, asyncio.run(build_summary(s, result))), corpus)
    assert out == tmp_path / "batch" / target
    for name in ("report.md", "results.json", "hardened_config.json", "corpus.json"):
        assert (out / name).exists()
    for name in ("security.evalset.json", "utility.evalset.json"):
        EvalSet.model_validate_json((out / "evalsets" / name).read_text(encoding="utf-8"))
    assert "Held-out breach rate" in (out / "report.md").read_text(encoding="utf-8")
    assert (tmp_path / "latest" / target / "hardened_config.json").exists()

    breaches, total = asyncio.run(run_regression(s, out / "hardened_config.json", out / "corpus.json"))
    assert breaches == 0 and total > 0
    weak = tmp_path / "weak.json"
    SecurityConfig.baseline(get_target(target)).save(weak)
    assert asyncio.run(run_regression(s, weak, out / "corpus.json"))[0] > 0  # regression catches the weak config


def test_combined_report(tmp_path):
    results = [asyncio.run(run_pipeline(Settings(demo=True, target=t, out_dir=tmp_path), "b"))[0] for t in TARGETS]
    md = render_combined_markdown(results)
    assert all(get_target(t).company in md for t in TARGETS) and "Converged" in md


@pytest.mark.parametrize("target", list(TARGETS))
def test_braces_in_defender_prompt_do_not_break_the_agent(target):
    spec = get_target(target)
    cfg = SecurityConfig.baseline(spec)
    cfg.system_prompt = "Use {curly} braces and {{nested}} safely. " * 4
    agent = build_target(cfg, Settings(demo=True, target=target).model_for("target"), spec)
    tr = asyncio.run(run_conversation(agent, ["hello"], {"current_user": spec.default_user}))
    assert tr.error is None and tr.replies[0]


def test_model_resolution():
    pytest.importorskip("litellm")
    assert resolve_model("gemini-3.6-flash") == "gemini-3.6-flash"
    lite = resolve_model("bedrock/converse/us.meta.llama3-3-70b-instruct-v1:0")
    assert type(lite).__name__ == "LiteLlm"
    assert type(resolve_model("ollama_chat/llama3.1")).__name__ == "LiteLlm"
