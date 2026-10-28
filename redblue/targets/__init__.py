from __future__ import annotations

from .base import TargetSpec
from .finbank import SPEC as FINBANK
from .helpdesk import SPEC as HELPDESK
from .shopco import SPEC as SHOPCO

TARGETS: dict[str, TargetSpec] = {s.id: s for s in (SHOPCO, FINBANK, HELPDESK)}


def get_target(target_id: str) -> TargetSpec:
    try:
        return TARGETS[target_id]
    except KeyError:
        raise ValueError(f"unknown target {target_id!r}; choose from {', '.join(TARGETS)}") from None
