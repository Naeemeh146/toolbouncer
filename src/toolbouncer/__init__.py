"""toolbouncer: a bouncer at the door between an agent and its tools.

Allowlist, description fingerprints (rug-pull detection), least-privilege
scopes, argument rules, and Rule-of-Two egress control — enforced in code,
with a full audit log. Zero required dependencies, fully offline.
"""

from toolbouncer.attacks import AttackResult, run_attack_suite, run_benign_suite
from toolbouncer.gateway import (
    AuditEntry,
    Blocked,
    Gateway,
    Session,
    ToolSpec,
    max_value,
    path_within,
)
from toolbouncer.scan import scan_description

__version__ = "0.1.0"

__all__ = [
    "AttackResult",
    "AuditEntry",
    "Blocked",
    "Gateway",
    "Session",
    "ToolSpec",
    "__version__",
    "max_value",
    "path_within",
    "run_attack_suite",
    "run_benign_suite",
    "scan_description",
]
