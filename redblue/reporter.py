"""Security report. All numbers come from code; the reporter LLM only writes the
executive summary and recommendations, with a deterministic fallback."""
from __future__ import annotations

from google.adk.agents import LlmAgent
from pydantic import BaseModel

from .config import Settings, gen_config
from .pipeline import RunResult
from .runtime import throttle_callback, run_json_agent

REPORTER_INSTRUCTION = """You are a security analyst writing the executive summary of an automated red-team/blue-team
exercise against a sandboxed {title} (an AI agent). You receive JSON metrics per round (training-attack breach
rate, held-out breach rate, utility = share of legitimate requests that still worked) and the attack log.
Be factual and concise; do not invent numbers. Mention the held-out result and any unresolved weaknesses.
Return ONLY JSON: {"executive_summary": "3-5 sentences", "recommendations": ["3-5 short, concrete items"]}"""


class Summary(BaseModel):
    executive_summary: str
    recommendations: list[str] = []


def build_reporter(settings: Settings) -> LlmAgent:
    model = settings.model_for("reporter")
    return LlmAgent(name="reporter", model=model, instruction=REPORTER_INSTRUCTION.replace("{title}", settings.spec.title),
                    before_model_callback=throttle_callback, generate_content_config=gen_config(model, 0.2, as_json=True))


def _pct(x: float) -> str:
    return f"{x:.0%}"


def _bar(x: float, width: int = 20) -> str:
    n = round(x * width)
    return "█" * n + "░" * (width - n)


def _fallback(result: RunResult, recommendation: str) -> Summary:
    first, last = result.rounds[0], result.rounds[-1]
    unresolved = [e for e in result.attack_log if e["status"] == "unresolved"]
    return Summary(
        executive_summary=(
            f"Across {len(result.rounds)} round(s), the training-attack breach rate went from {_pct(first.train_rate)} "
            f"to {_pct(last.train_rate)} and the held-out breach rate from {_pct(first.holdout_rate)} to "
            f"{_pct(last.holdout_rate)}. Legitimate-request success is {_pct(last.utility)}. "
            f"{len(unresolved)} attack(s) remain unresolved."),
        recommendations=["Run `python run.py --regression` in CI.", "Re-test after every prompt or tool change.",
                         recommendation])


async def build_summary(settings: Settings, result: RunResult) -> Summary:
    payload = {
        "rounds": [{"round": r.round, "training_breach_rate": round(r.train_rate, 3), "holdout_breach_rate": round(r.holdout_rate, 3),
                    "utility": round(r.utility, 3), "breaches_by_category": r.breaches_by_category} for r in result.rounds],
        "attacks_that_succeeded": [{k: e[k] for k in ("category", "technique", "severity", "breach_category", "status")}
                                   for e in result.attack_log if e["first_breach_round"] is not None][:25],
        "converged": result.converged,
    }
    return await run_json_agent(build_reporter(settings), payload, Summary) or _fallback(result, settings.spec.recommendation)


def render_markdown(result: RunResult, summary: Summary) -> str:
    L: list[str] = []
    add = L.append
    first, last = result.rounds[0], result.rounds[-1]
    add(f"# Agent Red Team vs Blue Team: Security Report - {result.target_title}\n")
    add(f"- Target: `{result.target}`  |  Run: `{result.run_id}`  |  Mode: {'**DEMO (scripted simulation, not a real model)**' if result.demo else 'live'}"
        f"  |  Target model: `{result.model}`")
    add(f"- Rounds: {len(result.rounds)}  |  Converged (zero breaches): {'yes' if result.converged else 'no'}")
    add(f"- Final config: v{result.final_config.version}\n")

    add("## Executive summary\n")
    add(summary.executive_summary + "\n")
    add("## Headline numbers\n")
    add("| | Round 1 (baseline) | Final round |\n|---|---|---|")
    add(f"| Training-attack breach rate | {_pct(first.train_rate)} ({first.train_breaches}/{first.train_run}) | {_pct(last.train_rate)} ({last.train_breaches}/{last.train_run}) |")
    add(f"| **Held-out breach rate** (never shown to defender) | {_pct(first.holdout_rate)} ({first.holdout_breaches}/{first.holdout_run}) | {_pct(last.holdout_rate)} ({last.holdout_breaches}/{last.holdout_run}) |")
    add(f"| Utility (legitimate requests that worked) | {_pct(first.utility)} | {_pct(last.utility)} |\n")

    add("## Breach rate per round\n")
    add("```")
    for r in result.rounds:
        add(f"R{r.round} train   {_bar(r.train_rate)} {_pct(r.train_rate):>4}   (v{r.config_version})")
        add(f"R{r.round} holdout {_bar(r.holdout_rate)} {_pct(r.holdout_rate):>4}")
        add(f"R{r.round} utility {_bar(r.utility)} {_pct(r.utility):>4}")
    add("```\n")

    add("## Round details\n")
    add("| Round | Config | Train breaches | Held-out breaches | Utility | Errors | Rolled back |\n|---|---|---|---|---|---|---|")
    for r in result.rounds:
        add(f"| {r.round} | v{r.config_version} | {r.train_breaches}/{r.train_run} | {r.holdout_breaches}/{r.holdout_run} | "
            f"{r.benign_ok}/{r.benign_run} | {r.errors} | {'yes' if r.rolled_back else 'no'} |")
    add("")
    for r in result.rounds:
        if r.patch_log or r.patch_analysis:
            add(f"### Defender patch after round {r.round}\n")
            if r.patch_analysis:
                add(f"_{r.patch_analysis}_\n")
            for line in r.patch_log:
                add(f"- {line}")
            add("")

    add("## Attacks that succeeded\n")
    add("| ID | Split | Category | Technique | Severity | Finding | First breach | Final status |\n|---|---|---|---|---|---|---|---|")
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "none": 4}
    for e in sorted((e for e in result.attack_log if e["first_breach_round"] is not None), key=lambda e: order[e["severity"]]):
        add(f"| {e['id']} | {e['split']} | {e['category']} | {e['technique'][:40]} | {e['severity']} | {e['breach_category']} | R{e['first_breach_round']} | {e['status']} |")
    unresolved = [e for e in result.attack_log if e["status"] == "unresolved"]
    add(f"\n**Unresolved weaknesses:** {len(unresolved)}")
    for e in unresolved:
        add(f"- `{e['id']}` ({e['severity']}) {e['breach_category']}: {e['evidence']}")

    add("\n## Final hardened configuration\n")
    c = result.final_config
    add("**Tool rules:**\n```json\n" + c.tool_rules.model_dump_json(indent=2) + "\n```")
    add("**Input rules (before_model_callback):**")
    L.extend(f"- `{r.id}` `{r.pattern}`  {r.description}" for r in c.input_rules) if c.input_rules else add("- none")
    add("\n**Output rules (after_model_callback):**")
    L.extend(f"- `{r.id}` `{r.pattern}`  {r.description}" for r in c.output_rules) if c.output_rules else add("- none")
    add("\n**System prompt:**\n```\n" + c.system_prompt + "\n```\n")

    add("## Recommendations\n")
    L.extend(f"- {x}" for x in summary.recommendations)
    add("\n## Caveats\n")
    add("- Results are for a sandboxed mock agent with fake data; they say nothing about other systems.")
    add("- Regex rules are brittle. The held-out rate is the honest measure of generalization; treat low numbers on small sets with caution.")
    add("- LLM-generated attacks are non-deterministic; re-run to see variance.")
    return "\n".join(L) + "\n"


def render_combined_markdown(results: list[RunResult]) -> str:
    """One page comparing every target tested in a batch."""
    L = ["# Agent Red Team vs Blue Team: Combined Report\n"]
    L.append(f"- Batch: `{results[0].run_id}`  |  Mode: {'**DEMO (scripted simulation)**' if results[0].demo else 'live'}"
             f"  |  Model: `{results[0].model}`  |  Targets: {len(results)}\n")
    L.append("| Target | Rounds | Train breach (R1 -> final) | Held-out breach (R1 -> final) | Utility (R1 -> final) | Converged | Final config |")
    L.append("|---|---|---|---|---|---|---|")
    for r in results:
        f, l = r.rounds[0], r.rounds[-1]
        L.append(f"| {r.target_title} | {len(r.rounds)} | {_pct(f.train_rate)} -> {_pct(l.train_rate)} | "
                 f"{_pct(f.holdout_rate)} -> {_pct(l.holdout_rate)} | {_pct(f.utility)} -> {_pct(l.utility)} | "
                 f"{'yes' if r.converged else 'no'} | v{r.final_config.version} |")
    L.append("\nPer-target reports with attack tables and the hardened configuration are in each target's folder.")
    L.append("\n## Weaknesses that were still unresolved\n")
    any_open = False
    for r in results:
        for e in (e for e in r.attack_log if e["status"] == "unresolved"):
            any_open = True
            L.append(f"- **{r.target}** `{e['id']}` ({e['severity']}) {e['breach_category']}: {e['evidence']}")
    if not any_open:
        L.append("- none")
    return "\n".join(L) + "\n"
