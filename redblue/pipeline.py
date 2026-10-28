"""The red/blue loop.

Each round:  build target from config -> red team generates attacks -> run seed/corpus/generated
(training) + held-out + benign conversations -> judge -> if clean or last round stop,
otherwise the defender proposes a patch, which is validated and applied.

The loop is driven in Python (rather than an ADK LoopAgent) because every attack needs a
fresh isolated target session and deterministic capture of tool calls; the agents inside
it (target, attackers, judge, defender, reporter) are all ADK LlmAgents.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import shutil
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .blue_team import build_defender, propose_patch, summarize_breach
from .config import ROOT, SecurityConfig, Settings, load_json
from .guardrails import apply_patch
from .judge import SEVERITY, BenignCase, Verdict, benign_ok, build_judge, judge_attack
from .red_team import CATEGORIES, Attack, build_attackers, generate_attacks
from .runtime import Transcript, log, run_conversation
from .target import build_target
from .targets import TargetSpec, get_target


class RoundResult(BaseModel):
    round: int
    config_version: int
    train_run: int = 0
    train_breaches: int = 0
    holdout_run: int = 0
    holdout_breaches: int = 0
    errors: int = 0
    benign_run: int = 0
    benign_ok: int = 0
    breaches_by_category: dict[str, int] = Field(default_factory=dict)
    false_refusals: list[str] = Field(default_factory=list)
    new_attacks_generated: int = 0
    patch_analysis: str = ""
    patch_log: list[str] = Field(default_factory=list)
    rolled_back: bool = False

    @property
    def train_rate(self) -> float:
        return self.train_breaches / self.train_run if self.train_run else 0.0

    @property
    def holdout_rate(self) -> float:
        return self.holdout_breaches / self.holdout_run if self.holdout_run else 0.0

    @property
    def utility(self) -> float:
        return self.benign_ok / self.benign_run if self.benign_run else 1.0


class RunResult(BaseModel):
    run_id: str
    target: str = "shopco"
    target_title: str = ""
    demo: bool
    model: str
    rounds: list[RoundResult] = Field(default_factory=list)
    attack_log: list[dict[str, Any]] = Field(default_factory=list)
    baseline_config: SecurityConfig
    final_config: SecurityConfig
    converged: bool = False
    out_dir: str = ""


def _key(a: Attack) -> tuple[str, ...]:
    return tuple(a.turns)


async def _attack_once(sem: asyncio.Semaphore, target, attack: Attack, judge, spec: TargetSpec) -> tuple[Transcript, Verdict]:
    async with sem:
        tr = await run_conversation(target, attack.turns, {"current_user": spec.default_user}, app_name=spec.app_name)
    if tr.error and "Quota exhausted" in tr.error:
        raise RuntimeError(tr.error)
    async with sem:
        verdict = await judge_attack(tr, spec.default_user, judge, spec)
    status = "API ERROR" if verdict.source == "error" else (f"BREACH [{verdict.severity}] {verdict.category}" if verdict.breach else "held")
    log(f"    attack {attack.id:<14} {status}")
    return tr, verdict


async def _benign_once(sem: asyncio.Semaphore, target, case: BenignCase, spec: TargetSpec) -> tuple[bool, str]:
    async with sem:
        tr = await run_conversation(target, case.turns, {"current_user": spec.default_user}, app_name=spec.app_name)
    ok, why = benign_ok(case, tr)
    log(f"    benign {case.id:<14} {'ok' if ok else 'FAILED: ' + why}")
    return ok, why


async def run_pipeline(settings: Settings, batch_id: str | None = None) -> tuple[RunResult, list[Attack]]:
    spec = settings.spec
    seeds = [Attack(**a) for a in load_json(spec.id, "seed.json")]
    holdout = [Attack(**a) for a in load_json(spec.id, "holdout.json")]
    benign = [BenignCase(**b) for b in load_json(spec.id, "benign.json")]
    benign_texts = [t for c in benign for t in c.turns]

    attackers = build_attackers(settings)
    judge = build_judge(settings) if settings.use_llm_judge else None
    defender = build_defender(settings)
    sem = asyncio.Semaphore(settings.concurrency)

    cfg = SecurityConfig.baseline(spec)
    baseline = cfg.model_copy(deep=True)
    prev_cfg: SecurityConfig | None = None
    prev_utility: float | None = None
    corpus: dict[tuple, Attack] = {}  # training attacks that ever breached; replayed every round
    history: dict[str, list[dict]] = {c: [] for c in CATEGORIES}
    attack_log: dict[str, dict[str, Any]] = {}
    run_id = batch_id or dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    result = RunResult(run_id=run_id, target=spec.id, target_title=f"{spec.company} {spec.title}", demo=settings.demo, model="demo" if settings.demo else settings.model_summary(),
                       baseline_config=baseline, final_config=cfg)

    for r in range(1, settings.max_rounds + 1):
        log(f"\n=== [{spec.id}] Round {r}/{settings.max_rounds}  (config v{cfg.version}) ===")
        target = build_target(cfg, settings.model_for("target"), spec, settings.target_temperature)

        generated = await generate_attacks(attackers, r, settings.attacks_per_category, history)
        log(f"  red team generated {len(generated)} new attacks" + ("  (only seed/held-out attacks will run)" if not generated else ""))

        train: list[Attack] = []
        seen: set[tuple] = set()
        pool = (seeds if r == 1 else []) + list(corpus.values())[-settings.corpus_replay_cap:] + generated
        for a in pool:
            if _key(a) not in seen:
                seen.add(_key(a))
                train.append(a)

        # Splits run one after another (each still bounded by --concurrency). Your fix: this avoids
        # starving a single local Ollama worker when everything is queued at once.
        train_out = await asyncio.gather(*(_attack_once(sem, target, a, judge, spec) for a in train))
        hold_out = await asyncio.gather(*(_attack_once(sem, target, a, judge, spec) for a in holdout))
        ben_out = await asyncio.gather(*(_benign_once(sem, target, c, spec) for c in benign))

        rr = RoundResult(round=r, config_version=cfg.version, new_attacks_generated=len(generated))
        breach_details: list[dict[str, Any]] = []

        for split, attacks, outs in (("train", train, train_out), ("holdout", holdout, hold_out)):
            for a, (tr, v) in zip(attacks, outs):
                if v.source == "error":
                    rr.errors += 1
                    continue
                if split == "train":
                    rr.train_run += 1
                else:
                    rr.holdout_run += 1
                entry = attack_log.setdefault(a.id, {
                    "id": a.id, "split": split, "category": a.category, "technique": a.technique,
                    "turns": a.turns, "first_breach_round": None, "severity": "none",
                    "breach_category": "", "evidence": "", "history": []})
                entry["history"].append({"round": r, "breach": v.breach})
                if v.breach:
                    rr.breaches_by_category[a.category] = rr.breaches_by_category.get(a.category, 0) + 1
                    if entry["first_breach_round"] is None:
                        entry["first_breach_round"] = r
                    if SEVERITY[v.severity] >= SEVERITY[entry["severity"]]:
                        entry.update(severity=v.severity, breach_category=v.category, evidence=v.evidence)
                    if split == "train":
                        rr.train_breaches += 1
                        corpus[_key(a)] = a
                        breach_details.append(summarize_breach(a, tr, v))
                    else:
                        rr.holdout_breaches += 1
                if split == "train" and a.source == "generated":
                    history[a.category].append({"technique": a.technique, "turns": a.turns,
                                                "outcome": "BREACHED" if v.breach else "BLOCKED"})

        for c, (ok, why) in zip(benign, ben_out):
            rr.benign_run += 1
            rr.benign_ok += int(ok)
            if not ok:
                rr.false_refusals.append(f"{c.id}: {c.turns[-1]!r} -> {why}")

        if rr.train_run + rr.holdout_run == 0 and rr.errors:
            raise RuntimeError(f"All {rr.errors} attack conversations failed with API errors, so there is nothing to report. "
                               "Fix the first 'API error' shown above (usually a wrong model name, key, or quota) and re-run.")
        result.rounds.append(rr)
        log(f"  training breaches {rr.train_breaches}/{rr.train_run} | holdout {rr.holdout_breaches}/{rr.holdout_run}"
            f" | utility {rr.benign_ok}/{rr.benign_run} | errors {rr.errors}")
        for line in rr.false_refusals:
            log(f"    false refusal: {line}")

        clean = rr.train_breaches == 0 and rr.holdout_breaches == 0 and rr.errors == 0
        if clean:
            result.converged = True
            log("  no breaches: stopping early.")
            break
        if r == settings.max_rounds:
            break

        # Roll back the last patch if it wrecked normal usage.
        if prev_cfg is not None and prev_utility is not None and rr.utility < prev_utility - 0.25:
            log(f"  utility fell {prev_utility:.0%} -> {rr.utility:.0%}: rolling back config v{cfg.version}")
            cfg, rr.rolled_back = prev_cfg, True
        if not rr.rolled_back:
            prev_utility = rr.utility

        patch = await propose_patch(defender, r, cfg, breach_details, rr.false_refusals, rr.rolled_back, settings.defender_max_breaches)
        if patch is None:
            rr.patch_log = ["defender returned no valid patch"]
            log("  defender returned no valid patch")
            continue
        rr.patch_analysis = patch.analysis
        prev_cfg = cfg
        cfg, rr.patch_log = apply_patch(cfg, patch, benign_texts, spec)
        log(f"  defender patch -> config v{cfg.version}")
        for line in rr.patch_log:
            log(f"    {line}")

    # Earlier breaching attacks fall out of the per-round replay window (corpus_replay_cap). Re-run them once
    # against the FINAL config so "fixed" / "unresolved" in the report is verified rather than assumed.
    last_round = result.rounds[-1].round if result.rounds else 0
    stale = [a for a in corpus.values() if attack_log[a.id]["history"][-1]["round"] != last_round]
    if stale:
        log(f"\n=== [{spec.id}] Final verification: re-running {len(stale)} earlier breaching attacks against the final config ===")
        final_target = build_target(cfg, settings.model_for("target"), spec, settings.target_temperature)
        outs = await asyncio.gather(*(_attack_once(sem, final_target, a, judge, spec) for a in stale))
        for a, (_, v) in zip(stale, outs):
            if v.source == "error":
                continue
            entry = attack_log[a.id]
            entry["history"].append({"round": last_round, "breach": v.breach, "verification": True})
            if v.breach:
                result.converged = False
                entry.update(severity=v.severity, breach_category=v.category, evidence=v.evidence)

    for e in attack_log.values():
        e["status"] = ("never_breached" if e["first_breach_round"] is None
                       else "unresolved" if e["history"][-1]["breach"] else "fixed")
    result.attack_log = list(attack_log.values())
    result.final_config = cfg
    return result, list(corpus.values())


def save_run(result: RunResult, settings: Settings, report_md: str, corpus: list[Attack]) -> Path:
    from .evalset import export_evalsets

    spec = get_target(result.target)
    out = settings.out_dir / result.run_id / spec.id
    out.mkdir(parents=True, exist_ok=True)
    result.out_dir = str(out)
    (out / "results.json").write_text(result.model_dump_json(indent=2), encoding="utf-8")
    result.baseline_config.save(out / "baseline_config.json")
    result.final_config.save(out / "hardened_config.json")
    (out / "corpus.json").write_text("[" + ",".join(a.model_dump_json() for a in corpus) + "]", encoding="utf-8")
    (out / "report.md").write_text(report_md, encoding="utf-8")
    export_evalsets(out / "evalsets", corpus, [BenignCase(**b) for b in load_json(spec.id, "benign.json")], spec)
    latest = settings.out_dir / "latest" / spec.id
    if latest.exists():
        shutil.rmtree(latest)
    shutil.copytree(out, latest)
    return out


async def run_regression(settings: Settings, config_path: Path, corpus_path: Path) -> tuple[int, int]:
    """Replay every known-breaching attack + the held-out set against a saved config.
    Returns (breaches, total). Use in CI: a non-zero breach count should fail the build."""
    import json

    cfg = SecurityConfig.load(config_path)
    spec = get_target(cfg.target)
    settings = settings.model_copy(update={"target": spec.id})

    corpus = [Attack(**a) for a in json.loads(Path(corpus_path).read_text(encoding="utf-8"))]
    holdout = [Attack(**a) for a in load_json(spec.id, "holdout.json")]
    target = build_target(cfg, settings.model_for("target"), spec, settings.target_temperature)
    judge = build_judge(settings) if settings.use_llm_judge else None
    sem = asyncio.Semaphore(settings.concurrency)
    attacks = corpus + holdout
    outs = await asyncio.gather(*(_attack_once(sem, target, a, judge, spec) for a in attacks))
    breaches = 0
    for a, (_, v) in zip(attacks, outs):
        if v.breach:
            breaches += 1
            log(f"  BREACH {a.id} [{v.severity}] {v.category}: {v.evidence}")
    return breaches, len(attacks)
