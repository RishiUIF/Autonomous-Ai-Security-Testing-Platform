"""Build a target's root_agent for `adk web` / `adk eval` from its latest hardened config."""
from __future__ import annotations

import os
from pathlib import Path

from .config import ROOT, SecurityConfig, Settings
from .target import build_target
from .targets import get_target


def load_root_agent(target_id: str):
    spec = get_target(target_id)
    path = Path(os.getenv(f"REDBLUE_CONFIG_{target_id.upper()}", ROOT / "outputs" / "latest" / target_id / "hardened_config.json"))
    cfg = SecurityConfig.load(path) if path.exists() else SecurityConfig.baseline(spec)
    settings = Settings(demo=os.getenv("REDBLUE_DEMO") == "1", target=target_id)
    return build_target(cfg, settings.model_for("target"), spec)
