"""Description scanning: a signal, not a boundary.

A tool description is text the *model* will read as instructions, supplied
by whoever runs the tool server. Hiding instructions in it ("tool
poisoning") is a demonstrated MCP attack. Scanning for known
hidden-instruction phrasings catches the lazy versions at registration
time and — just as important — produces a reviewable finding.

Detection alone is not a defence: a determined attacker phrases around any
pattern list. That is why the gateway treats a clean scan as *necessary,
not sufficient* — allowlists, fingerprints, scopes, argument rules and the
Rule of Two do the actual enforcing.
"""

from __future__ import annotations

import re

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("ignore_instructions", re.compile(r"ignore (all )?(previous|prior|above) instructions", re.I)),
    (
        "secret_exfiltration",
        re.compile(
            r"(send|pass|include|append).{0,60}(ssh|private key|password|secret|credential)", re.I
        ),
    ),
    (
        "read_sensitive_file",
        re.compile(r"read (the )?file.{0,40}(id_rsa|\.ssh|\.env|credentials)", re.I),
    ),
    ("hidden_directive", re.compile(r"<\s*(important|system|hidden)\s*>", re.I)),
    ("do_not_tell_user", re.compile(r"do not (tell|inform|mention to) the user", re.I)),
    (
        "side_channel_param",
        re.compile(r"(sidenote|side note|extra parameter).{0,60}(contents|file)", re.I),
    ),
]


def scan_description(description: str) -> list[str]:
    """Return the names of any hidden-instruction patterns found (possibly none)."""
    return [name for name, pattern in _PATTERNS if pattern.search(description)]
