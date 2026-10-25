"""A two-minute tour: one allowed call, and three blocked ones, with reasons."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from toolbouncer import Blocked, Gateway, Session, max_value  # noqa: E402


def main() -> None:
    gw = Gateway()
    gw.add_tool("get_weather", "Get the weather for a city.", lambda city: f"sunny in {city}")
    gw.add_tool(
        "refund",
        "Refund an order (max $100).",
        lambda order_id, amount: "refunded",
        scopes=frozenset({"payment:write"}),
        arg_rules=(max_value("amount", 100),),
    )
    gw.add_tool(
        "web_fetch",
        "Fetch a public page.",
        lambda url: "a page with opinions",
        untrusted_output=True,
    )
    gw.add_tool(
        "read_file",
        "Read a file.",
        lambda path: "private contents",
        scopes=frozenset({"fs:read"}),
        sensitive=True,
    )
    gw.add_tool(
        "send_email",
        "Send an email.",
        lambda to, body: "sent",
        scopes=frozenset({"email:send"}),
        egress=True,
    )

    print("ALLOW:", gw.call("get_weather", {"city": "Toronto"}))

    for label, fn in [
        (
            "refund $500 (over the cap)",
            lambda: gw.call("refund", {"order_id": "9", "amount": 500}, scopes={"payment:write"}),
        ),
        ("call an unregistered tool", lambda: gw.call("dump_database", {"table": "users"})),
    ]:
        try:
            fn()
            print(label, "-> NOT blocked (unexpected)")
        except Blocked as b:
            print(f"BLOCK: {label} -> {b.reason_code}: {b.detail}")

    session = Session()
    gw.call("web_fetch", {"url": "https://news.example"}, session=session)
    gw.call("read_file", {"path": "/app/secret.txt"}, scopes={"fs:read"}, session=session)
    try:
        gw.call(
            "send_email",
            {"to": "someone@outside.example", "body": "summary"},
            scopes={"email:send"},
            session=session,
        )
        print("trifecta -> NOT blocked (unexpected)")
    except Blocked as b:
        print(f"BLOCK: untrusted page + private file + send email -> {b.reason_code}: {b.detail}")

    print("\nAudit log entries:", len(gw.audit_log))


if __name__ == "__main__":
    main()
