"""A bouncer at the door between an agent and its tools.

An agent that can call tools trusts those tools completely: it reads their
descriptions as instructions, hands them credentials, and acts on whatever
they return. That trust is exploitable — a tool description can hide
instructions ("tool poisoning"), a trusted tool can change its description
after approval (a "rug pull"), an untrusted web page can talk the agent
into sending private data out (the "lethal trifecta": untrusted content +
private data + external communication in one session).

:class:`Gateway` sits in front of every tool call and enforces, in code —
not in a prompt — the rules a prompt cannot guarantee:

* **Allowlist** — only registered tools can be called at all.
* **Description fingerprinting** — each tool's name/description/schema is
  hashed at registration and pinned; if it changes later, calls are
  blocked until a human re-pins.
* **Least-privilege scopes** — a tool declares the scopes it needs; the
  caller must hold them.
* **Argument rules** — per-tool checks on arguments (amount caps, paths
  confined to a root, ...) run before the tool does.
* **Rule of Two / trifecta control** — a session that has both consumed
  untrusted content and touched sensitive data may not use an egress tool
  (send/post/fetch out) without explicit human approval; and a registered
  secret value may never appear in an egress call's arguments at all.
* **Audit log** — every decision, allow or block, with its reason.

The gateway is transport-agnostic: register the tools of an MCP server (or
any function-calling backend) and route calls through :meth:`Gateway.call`.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from toolbouncer.scan import scan_description

Handler = Callable[..., Any]
ArgRule = Callable[[dict[str, Any]], "str | None"]


class Blocked(Exception):
    """Raised when the gateway refuses a tool call.

    ``reason_code`` is one of: ``not_allowlisted``, ``description_scan``,
    ``rug_pull``, ``missing_scope``, ``arg_rule``, ``trifecta``,
    ``secret_egress``.
    """

    def __init__(self, reason_code: str, tool: str, detail: str) -> None:
        self.reason_code = reason_code
        self.tool = tool
        self.detail = detail
        super().__init__(f"Blocked {tool!r} ({reason_code}): {detail}")


@dataclass
class ToolSpec:
    """A registered tool and its security profile."""

    name: str
    description: str
    handler: Handler
    scopes: frozenset[str] = frozenset()
    arg_rules: tuple[ArgRule, ...] = ()
    schema: str = ""
    #: This tool's output is untrusted content (e.g. web pages, third-party data).
    untrusted_output: bool = False
    #: This tool can reach sensitive/private data.
    sensitive: bool = False
    #: This tool can send data outside the system (email, HTTP post, ...).
    egress: bool = False

    @property
    def fingerprint(self) -> str:
        """Hash of everything the model sees about this tool."""
        payload = f"{self.name}\n{self.description}\n{self.schema}"
        return hashlib.sha256(payload.encode()).hexdigest()


@dataclass
class Session:
    """What one agent session has touched so far (the trifecta legs)."""

    saw_untrusted: bool = False
    touched_sensitive: bool = False
    secrets: set[str] = field(default_factory=set)
    human_approved_egress: bool = False

    def register_secret(self, value: str) -> None:
        """Mark a value that must never leave via an egress tool."""
        if value:
            self.secrets.add(value)


@dataclass(frozen=True)
class AuditEntry:
    ts: float
    tool: str
    decision: str  # "allow" | "block"
    reason_code: str | None
    detail: str
    arg_keys: tuple[str, ...]


class Gateway:
    """Enforcing gateway in front of a set of registered tools."""

    def __init__(self, *, strict_description_scan: bool = True) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._pinned: dict[str, str] = {}
        self.strict_description_scan = strict_description_scan
        self.audit_log: list[AuditEntry] = []

    # -- registration -----------------------------------------------------

    def register(self, spec: ToolSpec) -> ToolSpec:
        """Register a tool, scan its description, and pin its fingerprint.

        In strict mode a description containing hidden-instruction patterns
        (see :mod:`toolbouncer.scan`) is refused registration outright.
        """
        findings = scan_description(spec.description)
        if findings and self.strict_description_scan:
            raise Blocked(
                "description_scan",
                spec.name,
                f"description contains hidden-instruction patterns: {', '.join(findings)}",
            )
        self._tools[spec.name] = spec
        self._pinned[spec.name] = spec.fingerprint
        return spec

    def add_tool(
        self,
        name: str,
        description: str,
        handler: Handler,
        **profile: Any,
    ) -> ToolSpec:
        """Convenience wrapper around :meth:`register`."""
        return self.register(
            ToolSpec(name=name, description=description, handler=handler, **profile)
        )

    def update_description(self, name: str, new_description: str, *, repin: bool = False) -> None:
        """Change a tool's description (simulating a server-side update).

        Without ``repin=True`` the next call is blocked as a rug pull: the
        tool the human approved is no longer the tool being offered.
        """
        spec = self._tools[name]
        spec.description = new_description
        if repin:
            self._pinned[name] = spec.fingerprint

    # -- calling ----------------------------------------------------------

    def call(
        self,
        name: str,
        args: dict[str, Any] | None = None,
        *,
        scopes: frozenset[str] | set[str] = frozenset(),
        session: Session | None = None,
    ) -> Any:
        """Route one tool call through every check, then (maybe) run it."""
        args = dict(args or {})
        session = session if session is not None else Session()
        try:
            result = self._call_checked(name, args, frozenset(scopes), session)
        except Blocked as blocked:
            self._audit(name, "block", blocked.reason_code, blocked.detail, args)
            raise
        self._audit(name, "allow", None, "", args)
        return result

    def _call_checked(
        self, name: str, args: dict[str, Any], scopes: frozenset[str], session: Session
    ) -> Any:
        spec = self._tools.get(name)
        if spec is None:
            raise Blocked("not_allowlisted", name, "tool is not registered with the gateway")

        if spec.fingerprint != self._pinned.get(name):
            raise Blocked(
                "rug_pull",
                name,
                "tool description/schema changed after it was pinned; "
                "a human must review and re-pin before it can be called",
            )

        missing = spec.scopes - scopes
        if missing:
            raise Blocked(
                "missing_scope", name, f"caller lacks required scope(s): {sorted(missing)}"
            )

        for rule in spec.arg_rules:
            problem = rule(args)
            if problem:
                raise Blocked("arg_rule", name, problem)

        if spec.egress:
            self._check_egress(name, args, session)

        result = spec.handler(**args)

        if spec.untrusted_output:
            session.saw_untrusted = True
        if spec.sensitive:
            session.touched_sensitive = True
        return result

    def _check_egress(self, name: str, args: dict[str, Any], session: Session) -> None:
        # A known secret value must never leave, approval or not.
        blob = json.dumps(args, default=str)
        for secret in session.secrets:
            if secret in blob:
                raise Blocked("secret_egress", name, "arguments contain a registered secret value")
        # Rule of Two: untrusted content + sensitive data + egress in one
        # session needs a human, because that is exactly the combination a
        # poisoned page needs to exfiltrate private data.
        if (
            session.saw_untrusted
            and session.touched_sensitive
            and not session.human_approved_egress
        ):
            raise Blocked(
                "trifecta",
                name,
                "session has consumed untrusted content and touched sensitive data; "
                "egress requires explicit human approval (Rule of Two)",
            )

    # -- audit --------------------------------------------------------------

    def _audit(
        self, tool: str, decision: str, reason: str | None, detail: str, args: dict[str, Any]
    ) -> None:
        self.audit_log.append(
            AuditEntry(
                ts=time.time(),
                tool=tool,
                decision=decision,
                reason_code=reason,
                detail=detail,
                arg_keys=tuple(sorted(args)),
            )
        )

    def audit_json(self) -> str:
        """The audit log as JSON — who tried what, and what the bouncer decided."""
        return json.dumps(
            [entry.__dict__ | {"arg_keys": list(entry.arg_keys)} for entry in self.audit_log],
            indent=2,
        )


# -- ready-made argument rules ---------------------------------------------


def max_value(arg: str, limit: float) -> ArgRule:
    """Reject calls where ``args[arg]`` exceeds ``limit`` (e.g. a refund cap)."""

    def rule(args: dict[str, Any]) -> str | None:
        value = args.get(arg)
        if isinstance(value, (int, float)) and value > limit:
            return f"{arg}={value} exceeds the cap of {limit}"
        return None

    return rule


def path_within(arg: str, root: str) -> ArgRule:
    """Reject calls where ``args[arg]`` is not a path inside ``root``."""

    def rule(args: dict[str, Any]) -> str | None:
        value = args.get(arg)
        if isinstance(value, str):
            normalized = value.replace("\\", "/")
            if ".." in normalized.split("/") or not (
                normalized == root or normalized.startswith(root.rstrip("/") + "/")
            ):
                return f"{arg}={value!r} is outside the allowed root {root!r}"
        return None

    return rule
