"""Local web UI for the red-team / blue-team lab (FastAPI; ships with google-adk, nothing extra to install).

The UI starts `run.py` as a subprocess and streams its output, so there is one code path for CLI and UI.
It binds to 127.0.0.1 only: it can start model calls with your keys, so it must not be exposed.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from ..config import ROOT, SecurityConfig, Settings, load_json
from ..explain import Explainer, explain_result
from ..judge import objective_findings
from ..runtime import run_conversation
from ..target import build_target
from ..targets import TARGETS, get_target

load_dotenv(ROOT / ".env")
STATIC = Path(__file__).parent / "static"
MODEL_RE = re.compile(r"^[A-Za-z0-9_./:\-]{1,120}$")
BATCH_RE = re.compile(r"^[A-Za-z0-9_\-]{1,60}$")
FILES = {"report.md", "hardened_config.json", "baseline_config.json", "results.json", "corpus.json"}


def out_dir() -> Path:
    return Path(os.getenv("REDBLUE_OUT_DIR", ROOT / "outputs"))


class RunRequest(BaseModel):
    target: str = "all"
    demo: bool = True
    rounds: int = Field(3, ge=1, le=10)
    attacks_per_category: int = Field(2, ge=1, le=6)
    concurrency: int = Field(1, ge=1, le=8)
    rpm: float = Field(0, ge=0, le=600)
    no_llm_judge: bool = False
    model: str | None = None
    target_model: str | None = None
    attacker_model: str | None = None
    defender_model: str | None = None
    judge_model: str | None = None
    target_temperature: float | None = Field(None, ge=0, le=2)
    ollama_num_ctx: int | None = Field(None, ge=1024, le=131072)


class PlayRequest(BaseModel):
    target: str
    turns: list[str] = Field(min_length=1, max_length=5)
    demo: bool = True
    model: str | None = None
    batch: str | None = None  # which saved hardened config to use (default: latest)


# --------------------------------------------------------------------------- #
class Run:
    def __init__(self, req: RunRequest, batch: str):
        self.id, self.batch, self.req = uuid.uuid4().hex[:10], batch, req
        self.lines: list[str] = []
        self.events: list[dict[str, Any]] = []
        self.status = "starting"
        self.exit_code: int | None = None
        self.proc: subprocess.Popen | None = None
        self.explainer = Explainer()
        self.started = time.time()
        self.lock = threading.Lock()

    def command(self) -> list[str]:
        r = self.req
        cmd = [sys.executable, "-u", str(ROOT / "run.py"), "--target", r.target, "--rounds", str(r.rounds),
               "--attacks-per-category", str(r.attacks_per_category), "--concurrency", str(r.concurrency),
               "--batch-id", self.batch, "--out", str(out_dir())]
        if r.demo:
            cmd.append("--demo")
        if r.rpm:
            cmd += ["--rpm", str(r.rpm)]
        if r.no_llm_judge:
            cmd.append("--no-llm-judge")
        for flag, val in (("--model", r.model), ("--target-model", r.target_model), ("--attacker-model", r.attacker_model),
                          ("--defender-model", r.defender_model), ("--judge-model", r.judge_model)):
            if val:
                cmd += [flag, val]
        if r.target_temperature is not None:
            cmd += ["--target-temperature", str(r.target_temperature)]
        return cmd

    def start(self) -> None:
        env = {**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUNBUFFERED": "1"}
        if self.req.ollama_num_ctx:
            env["REDBLUE_OLLAMA_NUM_CTX"] = str(self.req.ollama_num_ctx)
        self.proc = subprocess.Popen(self.command(), cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, encoding="utf-8", errors="replace", bufsize=1)
        self.status = "running"
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self.proc and self.proc.stdout
        for raw in self.proc.stdout:
            with self.lock:
                self.lines.append(raw.rstrip("\n"))
                ev = self.explainer.feed(raw)
                if ev:
                    ev["i"] = len(self.events)
                    self.events.append(ev)
        code = self.proc.wait()
        with self.lock:
            self.exit_code = code
            if self.status != "stopped":
                self.status = "done" if code == 0 else "failed"

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.status = "stopped"
            self.proc.terminate()


RUNS: dict[str, Run] = {}


def current_run() -> Run | None:
    return next((r for r in RUNS.values() if r.status in ("starting", "running")), None)


# --------------------------------------------------------------------------- #
def ollama_status() -> dict[str, Any]:
    base = os.getenv("OLLAMA_API_BASE", "http://localhost:11434").rstrip("/")
    try:
        with urllib.request.urlopen(base + "/api/tags", timeout=1.5) as r:
            data = json.load(r)
        return {"up": True, "base": base, "models": sorted(m["name"] for m in data.get("models", []))}
    except Exception:  # noqa: BLE001
        return {"up": False, "base": base, "models": []}


def list_batches() -> list[dict[str, Any]]:
    base, out = out_dir(), []
    if not base.exists():
        return out
    for d in sorted((p for p in base.iterdir() if p.is_dir() and p.name != "latest"), key=lambda p: p.stat().st_mtime, reverse=True):
        targets = []
        for t in TARGETS:
            f = d / t / "results.json"
            if f.exists():
                try:
                    res = json.loads(f.read_text(encoding="utf-8"))
                    first, last = res["rounds"][0], res["rounds"][-1]
                    targets.append({"id": t, "converged": res.get("converged", False), "demo": res.get("demo", False), "model": res.get("model", ""),
                                    "holdout": [first["holdout_breaches"] / max(first["holdout_run"], 1), last["holdout_breaches"] / max(last["holdout_run"], 1)]})
                except Exception:  # noqa: BLE001
                    continue
        if targets:
            out.append({"batch": d.name, "targets": targets, "demo": targets[0]["demo"], "model": targets[0]["model"],
                        "mtime": int(d.stat().st_mtime)})
    return out


def _config_path(target: str, batch: str | None) -> Path | None:
    p = (out_dir() / batch / target / "hardened_config.json") if batch else (out_dir() / "latest" / target / "hardened_config.json")
    return p if p.exists() else None


async def play_one(settings: Settings, cfg: SecurityConfig, turns: list[str]) -> dict[str, Any]:
    spec = settings.spec
    agent = build_target(cfg, settings.model_for("target"), spec, settings.target_temperature)
    tr = await asyncio.wait_for(run_conversation(agent, turns, {"current_user": spec.default_user}, app_name=spec.app_name, retries=1), timeout=300)
    findings = objective_findings(tr, spec.default_user, spec)
    from ..explain import explain_breach
    from ..targets.base import GUARDRAIL_MARKER

    notes = []
    for c in tr.tool_calls:
        st = (c.response or {}).get("status")
        args = ", ".join(f"{k}={v!r}" for k, v in c.args.items())
        if st == "blocked":
            notes.append({"level": "good", "text": f"The tool {c.name}({args}) was stopped by a guardrail: {(c.response or {}).get('message', '')}"})
        elif st == "success":
            notes.append({"level": "info", "text": f"The tool {c.name}({args}) was executed."})
        else:
            notes.append({"level": "warn", "text": f"The tool {c.name}({args}) returned: {st}."})
    if any(GUARDRAIL_MARKER in r for r in tr.replies):
        notes.append({"level": "good", "text": "A message or reply filter stopped this conversation before it reached the model or the user."})
    return {"replies": tr.replies, "error": tr.error, "notes": notes, "tool_calls": [{"name": c.name, "args": c.args, "status": (c.response or {}).get("status")} for c in tr.tool_calls],
            "breaches": [{"category": f.category, "severity": f.severity, "text": explain_breach(f.category, f.evidence)} for f in findings]}


def create_app() -> FastAPI:
    app = FastAPI(title="Agent Red Team vs Blue Team")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return (STATIC / "index.html").read_text(encoding="utf-8")

    @app.get("/api/status")
    def status() -> dict[str, Any]:
        s = Settings()
        run = current_run()
        return {
            "gemini_key": bool(os.getenv("GOOGLE_API_KEY")), "aws_keys": bool(os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE")),
            "ollama": ollama_status(), "default_model": s.model, "running": run.id if run else None,
            "targets": [{"id": t.id, "title": t.title, "company": t.company, "persona": t.persona, "tools": [f.__name__ for f in t.tools],
                         "flags": t.flags, "limits": {k: v.description for k, v in t.limits.items()}} for t in TARGETS.values()],
        }

    @app.get("/api/targets/{target}/examples")
    def examples(target: str) -> dict[str, Any]:
        try:
            get_target(target)
        except ValueError:
            raise HTTPException(404, "unknown target") from None
        return {"attacks": [{"id": a["id"], "label": f"{a['category'].replace('_', ' ')}: {a['technique']}", "turns": a["turns"]}
                            for n in ("seed.json", "holdout.json") for a in load_json(target, n)],
                "normal": [{"id": b["id"], "label": "normal request", "turns": b["turns"]} for b in load_json(target, "benign.json")]}

    @app.post("/api/runs")
    def start_run(req: RunRequest) -> dict[str, Any]:
        if req.target != "all" and req.target not in TARGETS:
            raise HTTPException(400, "unknown target")
        for m in (req.model, req.target_model, req.attacker_model, req.defender_model, req.judge_model):
            if m and not MODEL_RE.match(m):
                raise HTTPException(400, f"invalid model name: {m!r}")
        if current_run():
            raise HTTPException(409, "a run is already in progress")
        run = Run(req, time.strftime("%Y%m%d-%H%M%S") + "-ui")
        RUNS[run.id] = run
        run.start()
        return {"id": run.id, "batch": run.batch, "command": " ".join(["python", "run.py"] + run.command()[3:])}

    @app.get("/api/runs/{rid}")
    def get_run(rid: str, since: int = 0, raw_since: int = 0) -> dict[str, Any]:
        run = RUNS.get(rid)
        if not run:
            raise HTTPException(404, "unknown run")
        with run.lock:
            return {"status": run.status, "exit_code": run.exit_code, "batch": run.batch, "events": run.events[since:], "next": len(run.events),
                    "raw": run.lines[raw_since:], "raw_next": len(run.lines), "targets_seen": run.explainer.targets_seen,
                    "round": run.explainer.round, "rounds_total": run.explainer.rounds_total, "target": run.explainer.target,
                    "total_targets": len(TARGETS) if run.req.target == "all" else 1, "seconds": int(time.time() - run.started)}

    @app.post("/api/runs/{rid}/stop")
    def stop_run(rid: str) -> dict[str, str]:
        run = RUNS.get(rid)
        if not run:
            raise HTTPException(404, "unknown run")
        run.stop()
        return {"status": run.status}

    @app.get("/api/batches")
    def batches() -> list[dict[str, Any]]:
        return list_batches()

    def _result_path(batch: str, target: str) -> Path:
        if not (BATCH_RE.match(batch) and target in TARGETS):
            raise HTTPException(404, "not found")
        f = out_dir() / batch / target / "results.json"
        if not f.exists():
            raise HTTPException(404, "not found")
        return f

    @app.get("/api/batches/{batch}/{target}")
    def batch_target(batch: str, target: str) -> dict[str, Any]:
        return explain_result(json.loads(_result_path(batch, target).read_text(encoding="utf-8")))

    @app.get("/api/batches/{batch}/{target}/file/{name}")
    def batch_file(batch: str, target: str, name: str):
        f = _result_path(batch, target).parent / name
        if name not in FILES or not f.exists():
            raise HTTPException(404, "not found")
        return FileResponse(f, filename=f"{target}-{name}")

    @app.post("/api/playground")
    async def playground(req: PlayRequest) -> JSONResponse:
        try:
            spec = get_target(req.target)
        except ValueError:
            raise HTTPException(404, "unknown target") from None
        if req.model and not MODEL_RE.match(req.model):
            raise HTTPException(400, "invalid model name")
        if req.batch and not BATCH_RE.match(req.batch):
            raise HTTPException(400, "invalid batch")
        settings = Settings(demo=req.demo, target=spec.id)
        if req.model:
            settings.model = req.model
        base_cfg = SecurityConfig.baseline(spec)
        path = _config_path(spec.id, req.batch)
        hard_cfg = SecurityConfig.load(path) if path else None
        before = await play_one(settings, base_cfg, req.turns)
        after = await play_one(settings, hard_cfg, req.turns) if hard_cfg else None
        return JSONResponse({"before": before, "after": after, "hardened_version": hard_cfg.version if hard_cfg else None,
                             "note": None if hard_cfg else "No hardened configuration found yet. Run a test first (Run tab)."})

    return app


app = create_app()
