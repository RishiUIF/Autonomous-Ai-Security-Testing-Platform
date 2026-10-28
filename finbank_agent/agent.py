"""Target agent 'finbank' for `adk web .` / `adk eval`. Uses outputs/latest/finbank/hardened_config.json if present, else the weak baseline.
Set REDBLUE_DEMO=1 for the offline scripted model (no API key)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # make `redblue` importable under the adk CLI

from redblue.agent_loader import load_root_agent

root_agent = load_root_agent("finbank")
