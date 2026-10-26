#!/usr/bin/env python3
"""Mathematical Scoring and Normalization Engine for Tunnel Studio Pro v2.0.
Strictly implements continuous, independent normalization curves (B1 / P0-5):
- S_tp: Continuous throughput score [0.0, 1.0] derived directly from throughput_mbps
- S_lat: Dynamic baseline latency overhead score relative to direct RTT
- S_jit: Continuous jitter score normalized up to 40ms threshold
- S_stab: Continuous 30-second session survival score
- Loss penalty: Quadratic penalty multiplier (1 - Loss%)^2 with smooth ramp gating
- Profile-weighted aggregation for Balanced, Gaming, and Ultra-Speed
"""

# Overhead is measured as a *fraction above the direct base RTT*: 1.5 means the tunnel takes 2.5x as
# long as an un-tunneled round trip, and that is where S_lat bottoms out at 0.0. Health reporting uses
# the raw ratio instead, so the two scales meet at LAT_OVERHEAD_CEILING + 1.0 - failover.py takes its
# DEGRADED threshold from here rather than from its own literal, or a tunnel would be reported HEALTHY
# while its benchmark latency score is already pinned to the floor.
LAT_OVERHEAD_CEILING = 1.5

def clamp(val: float, min_val: float, max_val: float) -> float:
    return max(min_val, min(max_val, val))

def compute_lat_score(lat_avg: float, base_rtt: float = 0.0) -> tuple[float, float]:
    """Latency score based on dynamic baseline RTT.
    Returns (score, overhead_ratio).
    """
    if base_rtt > 0.0:
        overhead = max(0.0, (lat_avg - base_rtt) / base_rtt)
        score = 1.0 - clamp(overhead / LAT_OVERHEAD_CEILING, 0.0, 1.0)
        return round(score, 4), round(overhead, 4)
    else:
        # Graceful dynamic fallback when base RTT is unknown
        delta = max(0.0, lat_avg - 40.0)
        score = 1.0 - clamp(delta / 120.0, 0.0, 1.0)
        return round(score, 4), 0.0

def compute_jit_score(jitter: float) -> float:
    """Continuous jitter score: 1.0 at 0ms, down to 0.0 at 40ms."""
    return round(1.0 - clamp(jitter / 40.0, 0.0, 1.0), 4)

def compute_throughput_score(throughput_mbps: float, bulk_step: int = 4,
                             throughput_measured: bool | None = None) -> tuple[float, bool]:
    """Continuous throughput score normalized up to 100 Mbps.
    Returns (score, passed_hard_gate).

    `throughput_measured` distinguishes "measured, and it is 0.0" from "never measured", and it has to
    stay a separate input: the scalar reaching here is the *weakest measured direction*, so a tunnel
    whose download leg completed and carried nothing arrives as 0.0. Treating that as "no iperf3 data"
    would fall through to the discrete ladder step and hand a starved direction the full throughput
    score for a 1 MB object that did arrive once. Left as None, a positive number means measured and
    zero means not, which is what every pre-split caller already passes.
    """
    if throughput_measured is None:
        throughput_measured = throughput_mbps > 0.0
    if throughput_measured:
        score = clamp(throughput_mbps / 100.0, 0.0, 1.0)
        passed_hard_gate = (bulk_step >= 4)
        return round(score, 4), passed_hard_gate
    else:
        # Fallback to discrete ladder step if throughput_mbps not provided
        step = clamp(int(bulk_step), 0, 4)
        score = step / 4.0
        passed_hard_gate = (step >= 4)
        return round(score, 4), passed_hard_gate

def compute_bulk_score(step_passed: int) -> tuple[float, bool]:
    """Legacy backward-compatible bulk ladder scoring interface."""
    return compute_throughput_score(0.0, bulk_step=step_passed)

def compute_stab_score(seconds_survived: float, target_duration: float = 30.0) -> float:
    """Session survival score over continuous sustained load."""
    return round(clamp(seconds_survived / target_duration, 0.0, 1.0), 4)

def compute_loss_penalty(loss_pct: float) -> float:
    """Quadratic penalty multiplier (1 - Loss/100)^2."""
    p = clamp(loss_pct / 100.0, 0.0, 1.0)
    return round((1.0 - p) ** 2, 4)

PROFILES = {
    "balanced": {"w_lat": 0.35, "w_jit": 0.20, "w_stab": 0.25, "w_tp": 0.20},
    "gaming": {"w_lat": 0.50, "w_jit": 0.30, "w_stab": 0.15, "w_tp": 0.05},
    "ultraspeed": {"w_lat": 0.25, "w_jit": 0.15, "w_stab": 0.20, "w_tp": 0.40}
}

def evaluate_tunnel_metrics(lat_avg: float, jitter: float, bulk_step: int,
                            seconds_survived: float, loss_pct: float,
                            profile: str = "balanced",
                            throughput_mbps: float = 0.0,
                            throughput_measured: bool | None = None,
                            base_rtt: float = 0.0) -> dict:
    """Evaluates all metrics and produces normalized score and qualification status
    customized by active optimization profile (balanced, gaming, ultraspeed).
    Uses dynamic baseline overhead, real continuous metrics, and active iperf3 throughput (P0-6).
    `throughput_mbps` is the weakest measured direction, never an average of the two.
    """
    s_lat, overhead_ratio = compute_lat_score(lat_avg, base_rtt=base_rtt)
    s_jit = compute_jit_score(jitter)
    tp_was_measured = (throughput_mbps > 0.0) if throughput_measured is None else bool(throughput_measured)
    s_tp, tp_gate_passed = compute_throughput_score(throughput_mbps, bulk_step=bulk_step,
                                                    throughput_measured=tp_was_measured)
    s_stab = compute_stab_score(seconds_survived)
    loss_penalty = compute_loss_penalty(loss_pct)

    # Smooth ramp penalty starting from 10% up to 25% (P0-4 harmonized)
    if loss_pct > 10.0 and loss_pct <= 25.0:
        ramp_multiplier = max(0.0, 1.0 - ((loss_pct - 10.0) / 15.0) * 0.5)
    elif loss_pct > 25.0:
        ramp_multiplier = 0.0
    else:
        ramp_multiplier = 1.0

    disqualified = False
    dq_reasons = []

    if not tp_gate_passed:
        disqualified = True
        dq_reasons.append("Failed 1MB bulk ladder hard-gate (stream stall/DPI freeze)")

    if loss_pct > 25.0:
        disqualified = True
        dq_reasons.append(f"Excessive sustained packet loss ({loss_pct:.1f}% > 25%)")

    if seconds_survived < 25.0:
        disqualified = True
        dq_reasons.append(f"Connection dropped under 25s ({seconds_survived:.1f}s) in sustained load test")

    # Compute scores for all available profiles with active w_tp component (P0-6)
    scores_by_profile = {}
    for p_name, w in PROFILES.items():
        base = (w["w_stab"] * s_stab) + (w["w_lat"] * s_lat) + (w["w_jit"] * s_jit) + (w["w_tp"] * s_tp)
        sc = base * loss_penalty * ramp_multiplier * 100.0
        scores_by_profile[p_name] = 0.0 if disqualified else round(sc, 2)

    active_profile = profile if profile in PROFILES else "balanced"
    final_score = scores_by_profile[active_profile]

    return {
        "score": final_score,
        "profile": active_profile,
        "scores_by_profile": scores_by_profile,
        "disqualified": disqualified,
        "dq_reasons": dq_reasons,
        "breakdown": {
            "s_lat": round(s_lat, 3),
            "s_jit": round(s_jit, 3),
            "s_bulk": round(s_tp, 3),
            "s_throughput_obs": round(s_tp, 3),
            "s_stab": round(s_stab, 3),
            "loss_penalty": round(loss_penalty, 3),
            "ramp_multiplier": round(ramp_multiplier, 3),
            "loss_pct": round(loss_pct, 1),
            "lat_avg": round(lat_avg, 1),
            "jitter_ms": round(jitter, 2),
            "seconds_survived": round(seconds_survived, 1),
            "throughput_mbps": round(throughput_mbps, 2),
            "throughput_measured": tp_was_measured,
            "base_rtt": round(base_rtt, 2),
            "overhead_ratio": round(overhead_ratio, 3)
        }
    }
