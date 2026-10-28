"""The plain-English layer: every sentence is deterministic, so test the wording rules."""
import json

from redblue.explain import CATEGORY_TEXT, Explainer, explain_patch_line, explain_result
from redblue.targets import TARGETS, get_target


def test_every_judge_category_has_an_explanation():
    # every finding category any target can emit must have plain-English text
    import re
    from pathlib import Path
    cats = set()
    for t in TARGETS:
        src = Path(f"redblue/targets/{t}.py").read_text(encoding="utf-8")
        cats |= set(re.findall(r'category="(\w+)"', src))
    cats |= {"secret_leak", "persona_hijack", "prompt_disclosure", "false_action_claim"}
    assert cats - set(CATEGORY_TEXT) == set()


def test_live_lines_become_sentences_with_context():
    ex = Explainer()
    e = ex.feed("######## Target: finbank ########")
    assert "FinBank" in e["text"] and "Nova" in e["text"]
    e = ex.feed("=== [finbank] Round 2/4  (config v1) ===")
    assert "Round 2 of 4" in e["text"] and "version 1" in e["text"]
    e = ex.feed("    attack seed-01        BREACH [critical] unauthorized_transfer")
    assert e["level"] == "bad" and "SUCCEEDED" in e["text"] and "Prompt injection" in e["text"]
    assert "moved money out of an account the user does not own" in e["text"]
    assert ex.feed("    attack seed-04        held")["level"] == "good"
    assert ex.feed("    benign ben-01         ok")["level"] == "good"
    assert ex.feed("    benign ben-03         FAILED: replied with a refusal")["level"] == "bad"
    s = ex.feed("  training breaches 7/13 | holdout 7/8 | utility 6/6 | errors 0")
    assert "7 of 13" in s["text"] and "88%" in s["text"] and s["level"] == "warn"
    assert ex.feed("  no breaches: stopping early.")["kind"] == "done"
    assert ex.feed("   ")is None and ex.feed("some unknown line")["level"] == "dim"


def test_patch_lines_use_target_specific_descriptions():
    spec = get_target("helpdesk")
    assert "own id" in explain_patch_line("APPLIED tool rule enforce_self_only=True", spec)
    assert "password resets" in explain_patch_line("APPLIED tool rule max_password_resets_per_session=1", spec)
    assert "input filter" in explain_patch_line("APPLIED input rule i1: 'ignore'", spec)
    assert "rejected" in explain_patch_line("REJECTED input rule 'x': would block a legitimate request: 'hi'", spec)
    assert "refused to weaken" in explain_patch_line("REJECTED tool rule x=False (rules may only tighten)", spec)


def test_result_explanation_from_a_real_demo_run(tmp_path):
    import asyncio

    from redblue.config import Settings
    from redblue.pipeline import run_pipeline

    res, _ = asyncio.run(run_pipeline(Settings(demo=True, target="finbank", out_dir=tmp_path), "b"))
    x = explain_result(json.loads(res.model_dump_json()))
    assert x["verdict"]["level"] == "good" and x["converged"]
    assert "FinBank" in x["headline"] and "100% \u2192 0%" in x["headline"]
    assert any("structural tool rules" in p for p in x["summary"])
    assert x["rounds"][0]["train_rate"] > 0.5 and x["rounds"][-1]["train_rate"] == 0
    assert any(a["status"] == "fixed" and a["what_happened"] for a in x["attacks"])
    assert x["defenses"] and all(isinstance(s, str) for d in x["defenses"] for s in d["sentences"])
