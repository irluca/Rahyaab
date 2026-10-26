"""Atomic protocol swap with a timed dead-man rollback (Phase 3).

FailoverManager.execute_failover is honest about what it is: a staged
switchover with a real service gap and no way back if the successor comes
up running-but-broken after the last stage. Hashem's panel closes that
hole with a 45-second auto-rollback armed on both hosts before the swap;
this module is an independent implementation of that safety shape, wrapped
around the existing failover rather than replacing it.

How it works:
1. Before anything is touched, each host gets a rollback guard: a small
   detached script that sleeps ROLLBACK_WINDOW_S and then, unless a commit
   marker has appeared, stops the candidate's units and starts the old
   protocol's units again. The guard lives on the host, not in this
   process - if the orchestrator dies mid-swap, the pair still rolls back.
2. The failover runs. A health verification decides the outcome.
3. Verified healthy inside the window: the commit marker is written on
   both hosts and the guards stand down. Anything else - failover error,
   failed verification, a commit that cannot be delivered - leaves the
   guards to fire, which is the safe direction: back to the tunnel that
   was working before the swap.

Split outcomes are possible (one host commits, the other's guard fires)
if connectivity dies between the two commits; the result reports that
plainly instead of claiming atomicity it cannot guarantee, and the pair
is left down-but-known for the monitor rather than half-switched silently.
"""

from __future__ import annotations

ROLLBACK_WINDOW_S = 45
GUARD_PATH = "/usr/local/bin/best_tunnel_rollback_guard.sh"
MARKER_PATH = "/run/best_tunnel_swap_committed"


def rollback_script(stop_new: list[str], start_old: list[str],
                    window_s: int = ROLLBACK_WINDOW_S,
                    marker: str = MARKER_PATH) -> str:
    """The dead-man script for one host. Pure text builder: the exact bytes a
    host will execute are pinned by the offline tests, because a guard that
    fires wrong is worse than no guard at all."""
    lines = [
        "#!/bin/bash",
        "# Tunnel Studio Pro swap rollback guard - armed before a protocol swap.",
        "# Fires unless the commit marker appears within the window.",
        f"sleep {int(window_s)}",
        f"if [ -f {marker} ]; then rm -f {marker}; exit 0; fi",
    ]
    lines += [f"systemctl stop {unit} 2>/dev/null || true" for unit in stop_new]
    lines += [f"systemctl start {unit} 2>/dev/null || true" for unit in start_old]
    lines.append(f"rm -f {marker}")
    return "\n".join(lines) + "\n"


def _side_units(plan: dict, side: str) -> list[str]:
    return list(plan.get(f"{side}_units") or [])


def arm_guard(runner, script: str) -> bool:
    """Install and launch one host's guard, detached from the SSH session so
    it survives both the session and this process."""
    install = (
        f"rm -f {MARKER_PATH}\n"
        f"cat > {GUARD_PATH} <<'EOF'\n{script}EOF\n"
        f"chmod 700 {GUARD_PATH}\n"
        f"nohup bash {GUARD_PATH} >/dev/null 2>&1 &\n"
        "echo ARMED")
    _rc, out, _ = runner.run(install, check=False, best_effort=True, timeout=30)
    return "ARMED" in (out or "")


def commit(runner) -> bool:
    _rc, out, _ = runner.run(f"touch {MARKER_PATH} && echo COMMITTED",
                             check=False, best_effort=True, timeout=20)
    return "COMMITTED" in (out or "")


def guarded_failover(pair: dict, current_protocol: str, target_protocol: str,
                     reason: str, *, ir_runner, fr_runner,
                     failover_fn, verify_fn,
                     window_s: int = ROLLBACK_WINDOW_S,
                     dry_run: bool = False,
                     plan_fn=None) -> dict:
    """Run failover_fn under rollback guards armed on both hosts.

    failover_fn(pair, current, target, reason, dry_run, ir_runner, fr_runner)
    must return a dict with a truthy/falsy "success". verify_fn() runs after
    a successful failover and returns True only for a tunnel that actually
    carries traffic. Both are seams so the orchestration is testable offline;
    the dashboard wires them to FailoverManager and the health checker.
    """
    import protocols

    plan = plan_fn or protocols.generate_deployment
    pair_id = pair.get("id", 1)
    frontend = pair.get("frontend_port", pair.get("frontend", 443))
    old_plan = plan(current_protocol, pair_id,
                    protocols.dial_address(pair["iran"], current_protocol),
                    protocols.dial_address(pair["foreign"], current_protocol),
                    frontend)
    new_plan = plan(target_protocol, pair_id,
                    protocols.dial_address(pair["iran"], target_protocol),
                    protocols.dial_address(pair["foreign"], target_protocol),
                    frontend)

    if dry_run:
        return {"success": True, "dry_run": True, "rollback": "not armed in dry run",
                "window_s": window_s}

    guards = {}
    for side, runner in (("iran", ir_runner), ("foreign", fr_runner)):
        script = rollback_script(_side_units(new_plan, side),
                                 _side_units(old_plan, side), window_s)
        guards[side] = arm_guard(runner, script)
    if not all(guards.values()):
        return {"success": False, "rollback": "arming failed",
                "guards": guards,
                "note": "the swap was not attempted: a swap without a working "
                        "guard on both hosts is exactly the stranding this "
                        "module exists to prevent"}

    result = failover_fn(pair, current_protocol, target_protocol, reason,
                         dry_run, ir_runner, fr_runner)
    verified = bool(result.get("success")) and bool(verify_fn())
    if not verified:
        return {"success": False, "rollback": "armed - hosts restore the "
                f"previous protocol within {window_s}s",
                "failover": result, "verified": False}

    commits = {"iran": commit(ir_runner), "foreign": commit(fr_runner)}
    if all(commits.values()):
        return {"success": True, "rollback": "committed", "failover": result}
    return {"success": False, "rollback": "split commit", "commits": commits,
            "note": "one host did not acknowledge the commit and will roll "
                    "back on its guard timer; the pair needs a health check "
                    "before any further swap"}
