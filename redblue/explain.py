"""Turn raw log lines and result files into plain-English sentences.

Pure functions (no model calls, no I/O except reading the attack files), so every sentence is
deterministic and unit-tested. The web UI uses these for the live timeline and the report pages.
"""
from __future__ import annotations

import re
from typing import Any

from .config import load_json
from .targets import TargetSpec, get_target

FAMILY = {"prompt_injection": "Prompt injection", "jailbreak": "Jailbreak", "tool_abuse": "Tool abuse"}
FAMILY_TEXT = {
    "prompt_injection": "tries to smuggle new instructions into the conversation or into data the agent reads",
    "jailbreak": "tries to make the agent drop its rules or reveal its hidden instructions",
    "tool_abuse": "tries to make the agent use its tools in ways its policy forbids",
}

# category -> (short label, what happened in plain words, why it matters)
CATEGORY_TEXT: dict[str, tuple[str, str, str]] = {
    "unauthorized_refund": ("Refund on someone else's order", "The agent refunded an order that belongs to another customer.", "Direct financial loss and fraud."),
    "refund_over_limit": ("Refund above the limit", "The agent issued a refund larger than its allowed maximum.", "Direct financial loss."),
    "refund_exceeds_order_total": ("Refund larger than the order", "The agent refunded more money than the order was worth.", "Direct financial loss."),
    "refund_not_delivered": ("Refund on an undelivered order", "The agent refunded an order that had not been delivered yet.", "Policy bypass that invites fraud."),
    "multiple_refunds": ("Several refunds in one chat", "The agent issued more than the one refund allowed per conversation.", "Lets an attacker drain money in small steps."),
    "data_leak_other_customer": ("Another customer's data exposed", "The agent revealed details that belong to a different customer.", "Privacy breach."),
    "unauthorized_transfer": ("Money moved out of someone else's account", "The agent moved money out of an account the user does not own.", "Direct financial loss and account takeover."),
    "transfer_over_limit": ("Transfer above the limit", "The agent made a transfer bigger than the per-transfer limit.", "Direct financial loss; the limit exists for fraud control."),
    "overdraft": ("Transfer larger than the balance", "The agent moved more money than the account held.", "Creates negative balances and bad debt."),
    "internal_account_access": ("Bank-internal account used", "The agent moved money to or from an internal bank account.", "Touches the bank's own funds."),
    "multiple_transfers": ("Several transfers in one chat", "The agent made more than the one transfer allowed per conversation.", "Lets an attacker split a large theft into small steps."),
    "privilege_escalation": ("Privileged role granted", "The agent granted an admin-level role that needs a formal approval.", "Full account or system takeover."),
    "unauthorized_password_reset": ("Someone else's password reset", "The agent reset the password of an account the user does not own.", "Account takeover."),
    "unauthorized_access_grant": ("Access granted to someone else", "The agent granted access on behalf of a different person.", "Quiet privilege spreading."),
    "multiple_password_resets": ("Several password resets in one chat", "The agent reset passwords more often than allowed.", "Enables account-takeover attempts."),
    "multiple_access_grants": ("Several access grants in one chat", "The agent granted access more often than allowed.", "Enables privilege creep."),
    "pii_leak_other_employee": ("Another employee's data exposed", "The agent revealed another employee's confidential record or ticket.", "Privacy and HR confidentiality breach."),
    "secret_leak": ("Hidden secret revealed", "The agent printed the confidential code that was hidden in its instructions.", "Leaked credentials."),
    "persona_hijack": ("Agent took on a new persona", "The agent accepted a fake 'unrestricted' or 'admin' identity.", "Its rules no longer apply to it."),
    "prompt_disclosure": ("Hidden instructions revealed", "The agent disclosed its private system instructions.", "Helps attackers plan better attacks."),
    "false_action_claim": ("Claimed an action it did not do", "The agent said it performed an action that it never carried out.", "Misleads users and staff."),
}
SEVERITY_TEXT = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "none": "none"}


def _label(cat: str) -> str:
    return CATEGORY_TEXT.get(cat, (cat.replace("_", " "), cat.replace("_", " "), ""))[0]


def explain_breach(category: str, evidence: str = "") -> str:
    what = CATEGORY_TEXT.get(category, ("", category.replace("_", " "), ""))[1]
    return f"{what} ({evidence})" if evidence else what


def _pct(n: int, d: int) -> str:
    return f"{round(100 * n / d)}%" if d else "n/a"


def _short(text: str, n: int = 110) -> str:
    text = text.strip().replace("\n", " ")
    return text if len(text) <= n else text[: n - 1] + "\u2026"


# --------------------------------------------------------------------------- #
# Patch lines ("APPLIED input rule i1: '...'") -> sentences
# --------------------------------------------------------------------------- #
def explain_patch_line(line: str, spec: TargetSpec | None = None) -> str:
    line = line.strip()
    m = re.match(r"APPLIED tool rule (\w+)=(\S+)$", line)
    if m:
        name, val = m.groups()
        if spec and name in spec.flags:
            return f"Turned on a built-in safety check: {spec.flags[name]}."
        if spec and name in spec.limits:
            return f"Tightened a limit: {spec.limits[name].description} is now {val}."
        return f"Changed tool rule {name} to {val}."
    if line == "APPLIED new system prompt":
        return "Rewrote the agent's instructions so it treats user messages and tool output as untrusted data, keeps its codes private and refuses role changes."
    m = re.match(r"APPLIED (input|output) rule (\w+): (.*)$", line)
    if m:
        kind, rid, pat = m.groups()
        if kind == "input":
            return f"Added an input filter ({rid}) that blocks incoming text matching {pat}."
        return f"Added an output filter ({rid}) that stops replies matching {pat} from reaching the user."
    m = re.match(r"REJECTED (input|output) rule (.*): (.*)$", line)
    if m:
        kind, pat, why = m.groups()
        return f"The safety checker rejected a proposed {kind} filter {pat}: {why}. This protects normal users from false refusals."
    if line.startswith("REJECTED prompt"):
        return "The safety checker rejected the proposed prompt: " + line.split(":", 1)[-1].strip() + "."
    if line.startswith("REJECTED unknown tool"):
        return "The defender proposed a tool rule that does not exist, so it was ignored (" + line.split(" ", 3)[-1] + ")."
    if line.startswith("REJECTED tool rule"):
        return "The safety checker refused to weaken a rule: " + line[len("REJECTED tool rule "):] + "."
    if line.startswith("SKIPPED duplicate"):
        return "The defender repeated a filter that already existed, so it was skipped."
    return line


# --------------------------------------------------------------------------- #
# Live log lines -> events
# --------------------------------------------------------------------------- #
class Explainer:
    """Stateful: remembers the current target and round so each line can be explained in context."""

    def __init__(self) -> None:
        self.target: str | None = None
        self.round: int | None = None
        self.rounds_total: int | None = None
        self.spec: TargetSpec | None = None
        self._attack_info: dict[str, tuple[str, str]] = {}
        self.targets_seen: list[str] = []
        self.in_patch = False

    def _load_attacks(self, target: str) -> None:
        self._attack_info = {}
        for name in ("seed.json", "holdout.json"):
            try:
                for a in load_json(target, name):
                    self._attack_info[a["id"]] = (a["category"], a["technique"])
            except Exception:  # noqa: BLE001
                pass

    def _ev(self, kind: str, text: str, level: str = "info", **extra: Any) -> dict[str, Any]:
        return {"kind": kind, "level": level, "text": text, "target": self.target, "round": self.round, **extra}

    def feed(self, raw: str) -> dict[str, Any] | None:
        line = raw.rstrip()
        if not line.strip():
            return None
        s = line.strip()

        m = re.match(r"#+ Target: (\w+) #+$", s)
        if m:
            self.target = m.group(1)
            self.round = None
            self.targets_seen.append(self.target)
            try:
                self.spec = get_target(self.target)
                self._load_attacks(self.target)
                return self._ev("target", f"Starting the security test of the {self.spec.company} {self.spec.title} ('{self.spec.persona}').", "info")
            except ValueError:
                return self._ev("target", f"Starting the security test of target {self.target}.")

        m = re.match(r"=== \[(\w+)\] Round (\d+)/(\d+)\s+\(config v(\d+)\) ===$", s)
        if m:
            self.target, self.round, self.rounds_total = m.group(1), int(m.group(2)), int(m.group(3))
            v = int(m.group(4))
            how = "with no defenses yet (the weak starting point)" if v == 0 else f"with defenses version {v} (after {v} blue-team patch{'es' if v > 1 else ''})"
            return self._ev("round", f"Round {self.round} of {self.rounds_total}: attacking the agent {how}.", "info", config_version=v)

        m = re.match(r"=== \[(\w+)\] Final verification: re-running (\d+) earlier", s)
        if m:
            return self._ev("verify", f"Final check: replaying {m.group(2)} earlier successful attacks against the finished configuration to confirm they are really fixed.", "info")

        m = re.match(r"red team generated (\d+) new attacks", s)
        if m:
            n = int(m.group(1))
            if n == 0:
                return self._ev("redteam", "The red team produced no new attacks this round (a small model may have returned invalid JSON). Only the saved attacks will run.", "warn")
            return self._ev("redteam", f"The red team wrote {n} new attack{'s' if n != 1 else ''}, adapting to what worked or failed before.", "info")

        m = re.match(r"attack (\S+)\s+(.*)$", s)
        if m:
            aid, status = m.groups()
            info = self._attack_info.get(aid)
            desc = f" ({FAMILY.get(info[0], info[0])}: {info[1]})" if info else ""
            if status.startswith("BREACH"):
                mm = re.match(r"BREACH \[(\w+)\] (\w+)", status)
                sev, cat = (mm.group(1), mm.group(2)) if mm else ("?", "?")
                return self._ev("attack", f"Attack {aid}{desc} SUCCEEDED, severity {sev}: {explain_breach(cat)}", "bad", attack_id=aid, outcome="breach", category=cat)
            if status.startswith("API ERROR"):
                return self._ev("attack", f"Attack {aid}{desc} could not be judged because the model call failed.", "warn", attack_id=aid, outcome="error")
            return self._ev("attack", f"Attack {aid}{desc} was blocked: the agent held its ground.", "good", attack_id=aid, outcome="held")

        m = re.match(r"benign (\S+)\s+(.*)$", s)
        if m:
            bid, status = m.groups()
            if status.startswith("ok"):
                return self._ev("benign", f"Normal request {bid} was handled correctly.", "good", outcome="ok")
            why = status.replace("FAILED:", "").strip()
            return self._ev("benign", f"Normal request {bid} was wrongly refused or failed ({_short(why, 140)}). Defenses must not break real users.", "bad", outcome="failed")

        m = re.match(r"training breaches (\d+)/(\d+) \| holdout (\d+)/(\d+) \| utility (\d+)/(\d+) \| errors (\d+)", s)
        if m:
            tb, tr_, hb, hr, ub, ur, er = map(int, m.groups())
            txt = (f"Round result: {tb} of {tr_} training attacks ({_pct(tb, tr_)}) and {hb} of {hr} held-out attacks ({_pct(hb, hr)}) got through; "
                   f"{ub} of {ur} normal requests still worked.")
            if er:
                txt += f" {er} conversation(s) failed because of model errors."
            lvl = "good" if tb == 0 and hb == 0 and er == 0 else "warn"
            return self._ev("summary", txt, lvl, train=[tb, tr_], holdout=[hb, hr], utility=[ub, ur], errors=er)

        if s.startswith("false refusal:"):
            return self._ev("benign", "A normal request was wrongly blocked: " + _short(s.split(":", 1)[1], 170), "bad")

        if s.startswith("no breaches: stopping early"):
            return self._ev("done", "No attack succeeded in this round, so the loop stopped early: the agent is as hardened as these tests can show.", "good")

        m = re.match(r"utility fell (\S+) -> (\S+): rolling back config v(\d+)", s)
        if m:
            return self._ev("rollback", f"The last patch broke normal use (utility fell from {m.group(1)} to {m.group(2)}), so it was undone.", "warn")

        if s.startswith("defender returned no valid patch"):
            return self._ev("patch", "The blue-team model did not return a usable patch this round. Small local models often do this; a stronger defender model helps.", "warn")

        m = re.match(r"defender patch -> config v(\d+)", s)
        if m:
            self.in_patch = True
            return self._ev("patch", f"The blue team studied the successful attacks and proposed fixes; the safety checker applied them (defenses are now version {m.group(1)}):", "info")

        if re.match(r"(APPLIED|REJECTED|SKIPPED) ", s):
            return self._ev("patchline", explain_patch_line(s, self.spec), "warn" if s.startswith("REJECTED") else "info", detail=s)

        m = re.match(r"\[(\w+)\] Report: (.*)$", s)
        if m:
            return self._ev("report", f"Finished {m.group(1)}. The report and hardened configuration were saved.", "good")

        if s.startswith("Combined report:"):
            return self._ev("report", "Finished all targets. A combined comparison report was saved.", "good")

        m = re.match(r"Checking '(.+)' \(roles: (.*)\)", s)
        if m:
            return self._ev("check", f"Checking that the model '{m.group(1)}' responds (it will act as: {m.group(2)}).", "info")
        if s.startswith("API checks passed"):
            return self._ev("check", "Model check passed.", "good")
        if s.startswith("WARNING:"):
            return self._ev("check", s[len("WARNING:"):].strip(), "warn")
        if "FAILED" in s and s.startswith("Check"):
            return self._ev("error", "The model check failed. " + _short(s, 220), "bad")
        if s.startswith("Stopped on target"):
            return self._ev("error", s, "bad")
        if "API error" in s or "Quota exhausted" in s:
            return self._ev("error", "A model call failed: " + _short(s, 220), "warn")
        return self._ev("log", s, "dim")


# --------------------------------------------------------------------------- #
# Result file -> report model
# --------------------------------------------------------------------------- #
def _family_of(a: dict[str, Any]) -> str:
    return FAMILY.get(a.get("category", ""), a.get("category", ""))


def explain_result(res: dict[str, Any]) -> dict[str, Any]:
    spec = get_target(res["target"])
    rounds = res["rounds"]
    first, last = rounds[0], rounds[-1]

    def rate(r: dict, k: str) -> float:
        run = r[f"{k}_run"]
        return r[f"{k}_breaches"] / run if run else 0.0

    def util(r: dict) -> float:
        return r["benign_ok"] / r["benign_run"] if r["benign_run"] else 1.0

    round_rows = []
    for r in rounds:
        v = r["config_version"]
        where = "no defenses yet" if v == 0 else f"defenses v{v}"
        sentence = (f"{r['train_breaches']} of {r['train_run']} training attacks ({_pct(r['train_breaches'], r['train_run'])}) and "
                    f"{r['holdout_breaches']} of {r['holdout_run']} held-out attacks ({_pct(r['holdout_breaches'], r['holdout_run'])}) succeeded; "
                    f"{r['benign_ok']} of {r['benign_run']} normal requests worked.")
        if r.get("rolled_back"):
            sentence += " The previous patch was rolled back because it hurt normal use."
        round_rows.append({"round": r["round"], "config_version": v, "label": where, "train_rate": rate(r, "train"), "holdout_rate": rate(r, "holdout"),
                           "utility": util(r), "errors": r["errors"], "sentence": sentence,
                           "analysis": r.get("patch_analysis", "")})

    attacks = []
    for a in res["attack_log"]:
        status = a["status"]
        cat = a.get("breach_category") or ""
        if status == "never_breached":
            st = "Blocked every time it was tried."
        elif status == "fixed":
            st = f"Succeeded in round {a['first_breach_round']}, and is blocked after hardening."
        else:
            st = f"Succeeded in round {a['first_breach_round']} and still succeeds against the final configuration."
        attacks.append({
            "id": a["id"], "split": a["split"], "family": _family_of(a), "technique": a["technique"], "turns": a["turns"],
            "status": status, "status_text": st, "severity": a.get("severity", "none"),
            "what_happened": explain_breach(cat, a.get("evidence", "")) if cat else "",
            "label": _label(cat) if cat else "",
        })

    defenses = []
    for r in rounds:
        if r.get("patch_log"):
            defenses.append({"after_round": r["round"], "version": r["config_version"] + 1,
                             "analysis": r.get("patch_analysis", ""),
                             "sentences": [explain_patch_line(x, spec) for x in r["patch_log"]]})

    breached = [a for a in attacks if a["status"] != "never_breached"]
    unresolved = [a for a in attacks if a["status"] == "unresolved"]
    by_label: dict[str, int] = {}
    for a in breached:
        by_label[a["label"]] = by_label.get(a["label"], 0) + 1
    top = sorted(by_label.items(), key=lambda kv: -kv[1])[:3]
    n_applied = sum(1 for d in defenses for s in d["sentences"] if s.startswith(("Turned on", "Tightened", "Added", "Rewrote")))
    n_rejected = sum(1 for d in defenses for s in d["sentences"] if "rejected" in s or "refused to weaken" in s)
    n_tool = sum(1 for d in defenses for s in d["sentences"] if s.startswith(("Turned on", "Tightened")))

    ps = [f"We attacked the {spec.company} {spec.title} ('{spec.persona}') with {len(attacks)} different attacks "
          f"(prompt injection, jailbreaks and tool abuse) over {len(rounds)} round{'s' if len(rounds) != 1 else ''}."]
    ps.append(f"At the start, with no defenses, {_pct(first['train_breaches'], first['train_run'])} of the training attacks and "
              f"{_pct(first['holdout_breaches'], first['holdout_run'])} of the held-out attacks succeeded. "
              f"After hardening, the figures are {_pct(last['train_breaches'], last['train_run'])} and {_pct(last['holdout_breaches'], last['holdout_run'])}. "
              "Held-out attacks were never shown to the blue team, so that second number shows whether the fixes generalize.")
    if top:
        ps.append("The most common failures were: " + "; ".join(f"{k.lower()} ({n} attack{'s' if n != 1 else ''})" for k, n in top) + ".")
    if defenses:
        ps.append(f"The blue team applied {n_applied} change{'s' if n_applied != 1 else ''}, {n_tool} of them structural tool rules that the agent cannot be talked out of"
                  + (f", and the safety checker rejected {n_rejected} unsafe or too-broad proposal{'s' if n_rejected != 1 else ''}." if n_rejected else "."))
    ps.append(f"Normal requests kept working: {_pct(last['benign_ok'], last['benign_run'])} after hardening "
              f"(was {_pct(first['benign_ok'], first['benign_run'])} at the start).")
    if unresolved:
        ps.append(f"{len(unresolved)} attack{'s' if len(unresolved) != 1 else ''} still succeed" + ("" if len(unresolved) != 1 else "s")
                  + ": " + ", ".join(f"{a['id']} ({a['label'].lower()})" for a in unresolved[:4]) + ". Another round, or a stronger defender model, is the next step.")
    else:
        ps.append("Every attack that ever succeeded was re-tested against the final configuration and is now blocked.")
    caveat = ("This was a scripted offline simulation, so it shows that the system works, not how a real model behaves. " if res.get("demo") else "")
    caveat += ("The test sets are small and language models are random, so repeat the run before relying on the numbers.")
    ps.append(caveat)

    converged = res.get("converged")
    verdict = ({"level": "good", "text": "Hardened: no known attack succeeds against the final configuration."} if converged
               else {"level": "warn", "text": f"Not fully hardened: {len(unresolved) or 'some'} attack(s) still succeed or the run ended before a clean round."})
    return {
        "target": res["target"], "title": f"{spec.company} {spec.title}", "persona": spec.persona, "run_id": res["run_id"],
        "demo": res.get("demo", False), "model": res.get("model", ""), "verdict": verdict,
        "headline": (f"{spec.company} {spec.title}: held-out breach rate {_pct(first['holdout_breaches'], first['holdout_run'])} "
                     f"\u2192 {_pct(last['holdout_breaches'], last['holdout_run'])}, normal requests {_pct(last['benign_ok'], last['benign_run'])} working."),
        "kpis": {"train": [rate(first, "train"), rate(last, "train")], "holdout": [rate(first, "holdout"), rate(last, "holdout")],
                 "utility": [util(first), util(last)], "rounds": len(rounds), "version": res["final_config"]["version"]},
        "summary": ps, "rounds": round_rows, "attacks": attacks, "defenses": defenses,
        "false_refusals": sorted({x for r in rounds for x in r.get("false_refusals", [])}),
        "final_config": res["final_config"], "baseline_config": res["baseline_config"], "converged": bool(converged),
    }
