"""Run the attack suite, the benign suite, and a latency check. Print a table.

Usage: python benchmarks/run_benchmarks.py
"""

import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from toolbouncer import Gateway, run_attack_suite, run_benign_suite  # noqa: E402


def main() -> None:
    results = run_attack_suite()
    off = sum(r.succeeded_without_gateway for r in results)
    on = sum(r.succeeded_with_gateway for r in results)
    print(f"ATTACKS: {len(results)} scenarios")
    for r in results:
        print(
            f"  {r.name:45s} no-gateway={'SUCCESS' if r.succeeded_without_gateway else 'failed'}  "
            f"gateway={'SUCCESS' if r.succeeded_with_gateway else 'blocked'}"
            f"{' (' + r.block_reason + ')' if r.block_reason else ''}"
        )
    print(
        f"  -> attack success: {off}/{len(results)} without gateway, "
        f"{on}/{len(results)} with gateway"
    )

    total, false_blocks = run_benign_suite()
    print(f"\nBENIGN: {total} legitimate tasks, {false_blocks} wrongly blocked")

    # Latency: direct call vs gateway call on a trivial tool.
    def noop() -> str:
        return "ok"

    direct_times, gateway_times = [], []
    gw = Gateway()
    gw.add_tool("noop", "Do nothing.", noop)
    for _ in range(200):
        t0 = time.perf_counter()
        noop()
        direct_times.append(time.perf_counter() - t0)
        t0 = time.perf_counter()
        gw.call("noop", {})
        gateway_times.append(time.perf_counter() - t0)
    added_ms = (statistics.median(gateway_times) - statistics.median(direct_times)) * 1000
    print(
        f"\nLATENCY: median added per call = {added_ms:.3f} ms "
        f"(gateway median {statistics.median(gateway_times) * 1000:.3f} ms, "
        f"direct median {statistics.median(direct_times) * 1000:.3f} ms, 200 runs)"
    )


if __name__ == "__main__":
    main()
