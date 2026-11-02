"""C-Tunnel-style jitter/loss weighting in the bench score.

A link is felt through eff = lat + 2*jitter + 20*loss_pct, and past
jitter 10 ms / loss 2% a stutter tax bites: without it, a fast but
stuttering path outranks a slower steady one on latency alone, which
is exactly the wrong failover choice. Clean measurements (low jitter,
no loss) must score exactly as before.
"""

from orchestrator import scoring


def test_effective_latency_formula():
    assert scoring.compute_effective_latency(60.0, 15.0, 5.0) == 190.0
    assert scoring.compute_effective_latency(90.0, 1.0, 0.0) == 92.0


def test_stability_penalty_is_one_for_steady_links():
    assert scoring.compute_stability_penalty(1.5, 0.0) == 1.0
    assert scoring.compute_stability_penalty(10.0, 2.0) == 1.0
    assert scoring.compute_stability_penalty(6.75, 0.0) == 1.0


def test_stability_penalty_falls_with_jitter_and_loss():
    assert scoring.compute_stability_penalty(20.0, 0.0) < 1.0
    assert scoring.compute_stability_penalty(2.0, 10.0) < 1.0
    assert (scoring.compute_stability_penalty(35.0, 15.0)
            < scoring.compute_stability_penalty(20.0, 5.0))


def test_steady_path_outranks_fast_stuttering_path():
    steady = scoring.evaluate_tunnel_metrics(
        90.0, 1.0, 4, 30.0, 0.0, profile="balanced",
        throughput_mbps=50.0, base_rtt=40.0)
    stuttering = scoring.evaluate_tunnel_metrics(
        60.0, 20.0, 4, 30.0, 5.0, profile="balanced",
        throughput_mbps=50.0, base_rtt=40.0)
    assert steady["score"] > stuttering["score"]
    assert steady["breakdown"]["eff_latency_ms"] < stuttering["breakdown"]["eff_latency_ms"]


def test_clean_scores_unchanged_and_loss_contracts_hold():
    clean = scoring.evaluate_tunnel_metrics(
        45.0, 2.0, 4, 30.0, 0.0, profile="balanced",
        throughput_mbps=50.0, base_rtt=40.0)
    assert clean["breakdown"]["stability_penalty"] == 1.0
    assert clean["breakdown"]["eff_latency_ms"] == 49.0
    penalized = scoring.evaluate_tunnel_metrics(
        45.0, 2.0, 4, 30.0, 22.0, profile="balanced",
        throughput_mbps=50.0, base_rtt=40.0)
    assert not penalized["disqualified"] and penalized["score"] > 0.0
    dq = scoring.evaluate_tunnel_metrics(
        45.0, 2.0, 4, 30.0, 26.0, profile="balanced",
        throughput_mbps=50.0, base_rtt=40.0)
    assert dq["disqualified"] and dq["score"] == 0.0
