#!/usr/bin/env python
"""Red team vs blue team loop for Google ADK agents (three built-in targets).

  python run.py --demo --target all          offline simulation of all 3 targets, no API key needed
  python run.py --target all                 live run (Gemini by default; see .env.example for Bedrock / Ollama)
  python run.py --target finbank --rounds 3  one target only
  python run.py --regression --target all    replay known attacks against each saved hardened config (CI)

Targets: shopco (retail support), finbank (banking assistant), helpdesk (IT/HR helpdesk), all
Models:  gemini-3.6-flash | bedrock/converse/<model-id> | ollama_chat/<model>   (via --model or REDBLUE_MODEL)
Hybrid:  --target-model ollama_chat/llama3.1:8b --model gemini-3.6-flash   (local target, cloud red/blue teams)
"""
import argparse
import asyncio
import datetime as dt
import os
import shutil
import sys
from pathlib import Path

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # python-dotenv ships with google-adk; this is just a safety net
    pass

from redblue.config import ROOT, Settings, provider_of
from redblue.pipeline import run_pipeline, run_regression, save_run
from redblue.reporter import build_summary, render_combined_markdown, render_markdown
from redblue.runtime import log, set_rpm
from redblue.targets import TARGETS


def credentials_problem(model: str) -> str | None:
    prov = provider_of(model)
    if prov == "gemini":
        if not (os.getenv("GOOGLE_API_KEY") or os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "").upper() == "TRUE"):
            return "No GOOGLE_API_KEY found. Put it in .env (see .env.example), or try: python run.py --demo"
    elif prov == "bedrock":
        has_keys = os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY")
        if not (has_keys or os.getenv("AWS_BEARER_TOKEN_BEDROCK") or os.getenv("AWS_PROFILE")):
            return "No AWS credentials found. Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY (and AWS_REGION_NAME) in .env."
        if not (os.getenv("AWS_REGION_NAME") or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")):
            return "No AWS region set. Add AWS_REGION_NAME=us-east-1 (or your Bedrock region) to .env."
    return None


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--target", default="all", choices=[*TARGETS, "all"], help="which agent(s) to test (default: all three)")
    p.add_argument("--demo", action="store_true", help="scripted offline simulation (no API calls)")
    p.add_argument("--regression", action="store_true", help="replay corpus + held-out set against the saved hardened config(s)")
    p.add_argument("--rounds", type=int, default=4)
    p.add_argument("--attacks-per-category", type=int, default=2)
    p.add_argument("--concurrency", type=int, default=3, help="lower this if you hit API rate limits")
    p.add_argument("--rpm", type=float, default=0, help="max LLM requests per minute (Gemini free tier: 4; 0 = unlimited)")
    p.add_argument("--no-llm-judge", action="store_true", help="objective checks only (fewer API calls)")
    p.add_argument("--model", default=None, help="model id (default: REDBLUE_MODEL or gemini-3.6-flash)")
    p.add_argument("--target-model", default=None, help="model for the agent under test (e.g. a local ollama_chat/... model)")
    p.add_argument("--attacker-model", default=None, help="model for the red team")
    p.add_argument("--judge-model", default=None, help="model for the optional LLM judge")
    p.add_argument("--target-temperature", type=float, default=None, help="sampling temperature for the target (e.g. 0.2 = more repeatable runs)")
    p.add_argument("--defender-model", default=None, help="model for the blue team (often a stronger cloud model)")
    p.add_argument("--batch-id", default=None, help="name of the output folder (default: timestamp); used by the web UI")
    p.add_argument("--out", type=Path, default=ROOT / "outputs")
    a = p.parse_args()

    targets = list(TARGETS) if a.target == "all" else [a.target]
    s = Settings(demo=a.demo, max_rounds=a.rounds, attacks_per_category=a.attacks_per_category,
                 concurrency=a.concurrency, use_llm_judge=not a.no_llm_judge, out_dir=a.out)
    if a.model:
        s.model = a.model
    if a.target_model:
        s.target_model = a.target_model
    if a.attacker_model:
        s.attacker_model = a.attacker_model
    if a.judge_model:
        s.judge_model = a.judge_model
    if a.target_temperature is not None:
        s.target_temperature = a.target_temperature
    if a.defender_model:
        s.defender_model = a.defender_model
    if provider_of(s.name_for("defender")).startswith("ollama"):
        s.defender_max_breaches = 4  # keep the defender prompt inside a small local context window

    if not a.demo:
        problem = next((pr for pr in (credentials_problem(n) for n in set(s.model_names().values())) if pr), None)
        if problem:
            log(problem)
            return 2
    set_rpm(a.rpm)

    if not a.demo:
        from redblue.preflight import check_api

        if not asyncio.run(check_api(s)):
            return 3
        if a.rpm:
            log(f"Throttled to {a.rpm:g} requests/min. A round makes ~50-80 calls per target, so expect a long run. "
                "Progress lines appear as each test finishes.")

    if a.regression:
        failed = 0
        for t in targets:
            cfg, corpus = a.out / "latest" / t / "hardened_config.json", a.out / "latest" / t / "corpus.json"
            if not cfg.exists():
                log(f"[{t}] no saved config at {cfg}; run the loop first.")
                failed += 1
                continue
            breaches, total = asyncio.run(run_regression(s.model_copy(update={"target": t}), cfg, corpus))
            log(f"\n[{t}] Regression: {breaches}/{total} attacks breached the config {cfg}")
            failed += bool(breaches)
        return 1 if failed else 0

    batch = a.batch_id or dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    results = []
    for t in targets:
        st = s.model_copy(update={"target": t})
        log(f"\n######## Target: {t} ########")
        try:
            result, corpus = asyncio.run(run_pipeline(st, batch))
        except RuntimeError as e:
            log(f"\nStopped on target {t}: {e}")
            if results:
                log("Reports for the targets that finished are still being saved.")
                break
            return 4
        summary = asyncio.run(build_summary(st, result))
        out = save_run(result, st, render_markdown(result, summary), corpus)
        results.append(result)
        log(f"\n[{t}] Report: {out / 'report.md'}\n      Hardened config: {out / 'hardened_config.json'}")

    if len(results) > 1:
        combined = render_combined_markdown(results)
        (a.out / batch / "combined_report.md").write_text(combined, encoding="utf-8")
        (a.out / "latest").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(a.out / batch / "combined_report.md", a.out / "latest" / "combined_report.md")
        log(f"\nCombined report: {a.out / batch / 'combined_report.md'}")
    return 0 if len(results) == len(targets) else 4


if __name__ == "__main__":
    sys.exit(main())
