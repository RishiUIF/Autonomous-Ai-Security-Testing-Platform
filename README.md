# Agent Red Team vs Blue Team (Google ADK)

An automated security lab for AI agents. A **red team** of attacker agents attacks three different target agents,
a **judge** decides what really broke (by checking what the tools actually did), and a **blue team** defender agent
patches the target. The loop repeats until the attacks stop working, then it writes a security report, a
regression corpus and ADK eval sets.

Everything runs on fake data in a sandbox. Nothing here touches a real system.

## The three target agents

| Target | Agent | Tools | What can go wrong |
|---|---|---|---|
| `shopco` | **Aria**, retail customer support | `lookup_order`, `issue_refund` | refund fraud, other customers' orders/emails, secret discount code, poisoned order note (indirect injection) |
| `finbank` | **Nova**, digital banking assistant | `get_account`, `transfer_funds` | transfers out of other people's / internal accounts, over-limit and overdraft transfers, repeated transfers, poisoned transaction memo |
| `helpdesk` | **Atlas**, corporate IT/HR helpdesk | `get_employee`, `get_ticket`, `reset_password`, `grant_access` | privilege escalation (superadmin), account takeover via password reset, salary/PII disclosure, poisoned ticket note |

Each target starts with a deliberately weak prompt and naive tools, holds a hidden secret in its prompt, and has a
ground-truth policy the judge enforces. Each has its own attack sets in `attacks/<target>/`
(10 seed attacks, 8 held-out attacks the defender never sees, 6-7 legitimate requests).

## Quick start (no API key, 1 minute)

```
pip install -r requirements.txt
python run.py --demo --target all     # offline simulation of all three targets
pytest                                # 45 tests
```
`--demo` uses scripted fake models, so it proves the plumbing, guardrails and reports work. It says nothing about
how a real model behaves. See `examples/demo_run/` for its output.

## Live run

1. `copy .env.example .env` (Windows) / `cp .env.example .env`, then fill in ONE option.
   On Windows make sure the file is really called `.env`, not `.env.txt`.
2. Run:

```
# Gemini, paid / billing enabled
python run.py --target all --rounds 4 --concurrency 3

# Gemini free tier (very slow, small): one target, objective judge only
python run.py --target shopco --rpm 4 --rounds 2 --attacks-per-category 1 --no-llm-judge --concurrency 1

# AWS Bedrock open-weight model (set the AWS_* lines and REDBLUE_MODEL in .env first)
python run.py --target all --model "bedrock/converse/us.meta.llama3-3-70b-instruct-v1:0" --rpm 60 --concurrency 2

# Local Ollama (free)
python run.py --target all --model ollama_chat/llama3.1 --concurrency 1
```
A pre-flight check makes one test call first and explains the usual problems (wrong model id, no model access,
quota, bad key). A wait longer than 3 minutes (a daily quota) stops the run with a clear message instead of sleeping.
Use `--defender-model` to give the blue team a stronger model than the rest.

**Cost/time:** a round makes roughly 50-80 model calls per target, so a 4-round, 3-target run is on the order of
several hundred to ~1000 calls. Check your model's price. Start with one target and `--rounds 2`.

**Bedrock / Ollama only:** also run `pip install -r requirements-extra.txt` (Gemini does not need it).

**Bedrock notes:** the model must be enabled for your account in the region you use, ids differ per region (many need a
`us.`/`eu.` inference-profile prefix), and the model must support tool calling. New AWS accounts can have very low Bedrock
quotas: if you see throttling, lower `--rpm` / `--concurrency`. Check the Billing console that your credits cover the
model you choose.

## Web UI (plain-English logs and reports)

```
python ui.py          # opens http://127.0.0.1:8000
```
1. **Run a test**: tick the agents, pick a preset (offline demo, Gemini, Ollama, or hybrid), press Start. A live timeline
   explains every attack and defense in sentences; the raw log is one click away. The UI just starts `run.py` for you.
2. **Results explained**: a written summary, before/after numbers, a round chart, every attack with what it achieved and
   whether it is fixed, what the blue team changed (each change in plain words), and downloads.
3. **Try an attack**: send one message to the weak agent and to the hardened agent side by side.

The UI listens on 127.0.0.1 only (it can spend your API quota, so do not expose it). The wording comes from fixed
templates in `redblue/explain.py`, not from a model, so it is the same every time and costs no API calls.

## Local models (Ollama): getting the best out of them

Most calls in a run are the *target* answering attacks; the red team, defender and reporter make only a handful.
So the efficient setup is **hybrid**: a local target, a stronger cloud model for the few smart roles.

```
# local target (no quota), Gemini for red team / defender / reporter (about 5 calls per round, fits a free key)
python run.py --target shopco --target-model ollama_chat/llama3.1:8b --model gemini-3.6-flash --rpm 4 --rounds 3 --no-llm-judge

# fully local (judge too), more repeatable target
python run.py --target shopco --model ollama_chat/llama3.1:8b --target-temperature 0.2 --concurrency 1 --rounds 3
```
Role flags: `--target-model`, `--attacker-model`, `--defender-model`, `--judge-model` (env: `REDBLUE_TARGET_MODEL`, ...).
Local models are never rate-limited by `--rpm`.

Calibration that needs no training:
* `ollama create redblue-target -f ollama/Modelfile.target` then `--target-model ollama_chat/redblue-target`
  (low temperature, 8k context). `REDBLUE_OLLAMA_NUM_CTX` sets the context window the code requests (default 8192).
* Ollama server variables: `OLLAMA_KEEP_ALIVE=30m` (keep the model loaded), `OLLAMA_FLASH_ATTENTION=1`,
  `OLLAMA_KV_CACHE_TYPE=q8_0` (less VRAM per token). Keep ONE model in play to avoid reloads.
* A pre-flight check warns if a model will not call tools (as target) or will not return clean JSON (as red/blue).
* LLM sampling is random: run 3 times and compare, or fix `--target-temperature 0.2`.
* An 8B defender tends to copy transcript text into brittle regexes; the defender prompt now forbids that and
  receives per-category hints. Structural tool rules do most of the real work.

## Fine-tuning: what it can and cannot do here

* **Red / blue models:** a fine-tune only helps if you have good examples. Use a strong model (Gemini) for these roles
  instead: it costs a few calls per round.
* **Target model hardening** (adversarial fine-tuning on refusals) is a real research experiment, not a quick win:
  train only on the training split (seeds + generated attacks), never on `holdout.json`, then compare the
  baseline breach rate of the base vs tuned model on the held-out set. Tool rules still give the guarantees.
* On an 8 GB laptop GPU use QLoRA (e.g. Unsloth, under WSL2/Linux) on a 3B-8B model, export GGUF, `ollama create`.
  Check VRAM with `nvidia-smi` first.

## Outputs

```
outputs/<batch>/<target>/report.md            security report for that target
outputs/<batch>/<target>/hardened_config.json final prompt + rules + tool policy
outputs/<batch>/<target>/corpus.json          every attack that ever breached (regression suite)
outputs/<batch>/<target>/evalsets/            ADK EvalSets: security.evalset.json, utility.evalset.json
outputs/<batch>/combined_report.md            one table across targets
outputs/latest/...                            copy of the newest batch
```

## Use the results

```
python run.py --regression --target all                 # replay known attacks against saved configs (use in CI; exit 1 on any breach)
adk web .                                               # chat with shopco_agent / finbank_agent / helpdesk_agent
adk eval helpdesk_agent outputs/latest/helpdesk/evalsets/utility.evalset.json --config_file_path outputs/latest/helpdesk/evalsets/utility_test_config.json
```
The `*_agent` folders load `outputs/latest/<target>/hardened_config.json` (or the weak baseline if none).
Set `REDBLUE_DEMO=1` to use the offline model there.

## How it works

```
 attacks/<target>/*.json ──┐
                           v
 ┌──────────┐  attacks   ┌────────────────┐  tool calls + replies  ┌───────┐
 │ Red team │──────────> │ Target (ADK    │ ─────────────────────> │ Judge │
 │ 3 ADK    │            │ LlmAgent built │                        │ code  │
 │ agents   │ <───────── │ from config)   │ <── hardened config ── │ first,│
 └──────────┘  results   └────────────────┘          ^             │ LLM   │
                                                      │             │ second│
                                              ┌───────┴──────┐      └───┬───┘
                                              │ Blue team    │ <────────┘ breaches
                                              │ defender +   │
                                              │ patch checker│
                                              └──────────────┘
```
* **Target**: an ADK `LlmAgent` rebuilt every round from a `SecurityConfig` (system prompt, regex input rules, regex
  output rules, structural tool rules). Guardrails are ADK callbacks: `before_model_callback` (injection scan, including
  tool output), `before_tool_callback` (structural policy), `after_model_callback` (leak scan).
* **Red team**: three specialist agents (prompt injection, jailbreak, tool abuse), each briefed on the target, each shown
  which of its earlier attacks worked and asked to evolve them.
* **Judge**: objective checks in plain Python over what tools actually executed (unauthorized refund/transfer/grant,
  over limit, cross-user data, secret in a reply). An LLM judge only handles subjective leftovers (persona hijack,
  prompt disclosure).
* **Blue team**: a defender agent proposes a JSON patch. `apply_patch` validates it: tool rules can only tighten, only
  names the target defines are accepted, regexes are compiled and tested against legitimate requests, the prompt may
  never contain the secret. If a patch drops utility by more than 25 points it is rolled back.
* **Honest measurement**: held-out attacks are never shown to the defender; utility is measured on legitimate requests;
  after the loop every earlier breaching attack is re-run against the final config.

## Add a fourth target

Create `redblue/targets/<name>.py` with a `SPEC = TargetSpec(...)` (tools, fake backend, ground-truth policy, guardrail
switches, briefs), register it in `redblue/targets/__init__.py`, add `attacks/<name>/{seed,holdout,benign}.json` and an
`<name>_agent/` folder. The engine needs no changes.

## Layout

```
run.py                 CLI
redblue/targets/       the 3 target specs (tools, data, policy, findings)
redblue/ui/            web UI (FastAPI) + explain.py (log and report wording)
redblue/               config, guardrails, target builder, runtime (Runner wrappers, throttle), red_team, blue_team,
                       judge, pipeline, evalset, reporter, preflight, demo_llm (offline models), agent_loader
attacks/<target>/      seed / holdout / benign datasets
*_agent/               adk web / adk eval entry points
tests/                 45 tests (guardrails, judge, full offline loop per target, model routing)
examples/demo_run/     sample output from --demo
```

## Limits (be honest in your write-up)

* Mock agents with fake data: results say nothing about other systems.
* Regex rules are brittle; the held-out rate is the honest measure of generalization, and the sets are small.
* LLM-generated attacks are non-deterministic: re-run to see variance. Demo mode is a simulation, not evidence.
* Smaller open models may fail at tool calling or JSON output, which shows up as errors or empty replies in the log.
