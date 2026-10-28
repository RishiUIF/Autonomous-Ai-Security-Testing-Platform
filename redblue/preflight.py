"""Fail fast with a readable message if a key / model name is wrong, and warn early when a model
is too weak for its job (a target that cannot call tools, an attacker that cannot emit JSON)."""
from __future__ import annotations

from google.adk.agents import LlmAgent

from .config import Settings, provider_of, resolve_model
from .runtime import extract_json, log, run_conversation


def _available_models() -> list[str]:
    """Ask the Gemini API which models this key can call (best effort)."""
    try:
        from google import genai

        out = []
        for m in genai.Client().models.list():
            actions = getattr(m, "supported_actions", None) or []
            name = (m.name or "").replace("models/", "")
            if "generateContent" in actions and "gemini" in name and not any(
                    x in name for x in ("image", "tts", "live", "embedding", "audio", "robotics", "computer")):
                out.append(name)
        return sorted(out)
    except Exception:  # noqa: BLE001
        return []


def ping_tool(word: str) -> dict:
    """Echo a word back. Used only by the pre-flight tool-calling check.

    Args:
        word: Any word.

    Returns:
        A dict with status "success" and the word.
    """
    return {"status": "success", "word": word}


def _explain_failure(name: str, err: str) -> None:
    prov = provider_of(name)
    if prov == "bedrock":
        log("\nAWS Bedrock hints:\n"
            "  - AccessDenied / 'not authorized': enable the model in the Bedrock console (Model access / Model catalog) in THIS region,\n"
            "    and give your IAM user bedrock:InvokeModel permission.\n"
            "  - 'on-demand throughput isn't supported': use the inference-profile id, e.g. bedrock/converse/us.meta.llama3-3-70b-instruct-v1:0\n"
            "  - 'ResourceNotFound' / 'invalid model identifier': copy the exact model id from the console; ids differ per region.\n"
            "  - Throttling / 'Too many requests': new accounts have low quotas, so lower --rpm and --concurrency.\n"
            "  - Credentials: set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_REGION_NAME in .env.")
    elif prov.startswith("ollama"):
        if "does not support tools" in err:
            log("\nThis Ollama model cannot call tools, so it cannot be the target. Try: ollama pull qwen2.5:7b  or  ollama pull llama3.1:8b")
        elif "not found" in err.lower() or "404" in err:
            log("\nOllama does not have that model. Run `ollama list`, or `ollama pull <name>` (use the exact name after ollama_chat/).")
        else:
            log("\nOllama hints: is Ollama running (tray icon, or `ollama serve`)? Is the model pulled (`ollama list`)?\n"
                "  If Ollama is on another port/host, set OLLAMA_API_BASE=http://localhost:11434 in .env. Install extras: pip install -r requirements-extra.txt")
    elif "404" in err or "NOT_FOUND" in err:
        log("\nThe model name is not available (Google retires models regularly).")
        models = _available_models()
        if models:
            log("Models your key can use:\n  " + "\n  ".join(models))
        log("Set one in .env, e.g.  REDBLUE_MODEL=gemini-3.6-flash   (or pass --model NAME)")
    elif "429" in err or "RESOURCE_EXHAUSTED" in err:
        log("\nQuota exhausted: wait a minute, use --rpm 4, enable billing, or try another model (--model NAME).")
    else:
        log("\nCheck GOOGLE_API_KEY in .env, and your internet connection.")


async def check_model(name: str, roles: list[str]) -> bool:
    """Ping the model; then warn (never fail) if it looks too weak for the roles it will play."""
    log(f"Checking '{name}' (roles: {', '.join(roles)}) ...")
    model = resolve_model(name)
    tr = await run_conversation(LlmAgent(name="preflight", model=model, instruction="Reply with the single word OK."),
                                ["ping"], retries=0)
    if tr.error:
        log(f"\nCheck FAILED for '{name}': {tr.error[:500]}")
        _explain_failure(name, tr.error)
        return False

    if "target" in roles:
        agent = LlmAgent(name="preflight_tools", model=model, tools=[ping_tool],
                         instruction="You must call the ping_tool tool with word='alpha', then reply with the single word DONE.")
        tr = await run_conversation(agent, ["go"], retries=0)
        if tr.error and "does not support tools" in tr.error:
            log(f"\nCheck FAILED for '{name}': this model cannot call tools, so it cannot be the target.")
            _explain_failure(name, tr.error)
            return False
        if not tr.error and not any(c.name == "ping_tool" for c in tr.tool_calls):
            log(f"  WARNING: '{name}' did not call a simple tool when told to. As the target it will look safer than it is "
                "(it just won't act), and benign requests will fail. Prefer qwen2.5:7b or llama3.1:8b, or a cloud model.")
    if any(r in roles for r in ("attacker", "defender", "judge", "reporter")):
        agent = LlmAgent(name="preflight_json", model=model,
                         instruction='Reply with ONLY this JSON and nothing else: {"ok": true, "items": [1, 2]}')
        tr = await run_conversation(agent, ["go"], retries=0)
        try:
            ok = not tr.error and extract_json(tr.replies[0]).get("ok") is True
        except Exception:  # noqa: BLE001
            ok = False
        if not ok:
            log(f"  WARNING: '{name}' did not return clean JSON when asked. The red/blue agents will fail more often "
                "(look for 'not valid JSON' lines). A bigger model, or a cloud model for the defender, helps.")
    log("  ok")
    return True


async def check_api(settings: Settings) -> bool:
    by_model: dict[str, list[str]] = {}
    for role, name in settings.model_names().items():
        by_model.setdefault(name, []).append(role)
    for name, roles in by_model.items():
        if not await check_model(name, roles):
            return False
    log("API checks passed.\n")
    return True
