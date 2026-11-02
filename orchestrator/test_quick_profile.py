"""Quick-test profile: shorter stability window, no iperf3 legs.

The DPI gates (deploy, latency/jitter/loss probes, bulk ladder) stay,
so a quick score is comparable among quick scores — just not with a
full sweep's. Constants are restored after the test so no other test
sees the shortened window.
"""

import orchestrator.run_sweep as run_sweep


def test_apply_quick_profile_shortens_stability_and_skips_iperf3():
    import probe
    import engine
    old_samples = probe.STABILITY_SAMPLES
    old_window = probe.STABILITY_WINDOW
    old_iperf = engine.measure_iperf3_throughput
    try:
        run_sweep.apply_quick_profile()
        assert probe.STABILITY_SAMPLES == 10
        assert probe.STABILITY_WINDOW == 10.0
        assert probe.stability_cmd("10.0.0.1", 8898).count("10") >= 1
        stub = engine.measure_iperf3_throughput(None, None, "10.0.0.1")
        assert stub["available"] is False
    finally:
        probe.STABILITY_SAMPLES = old_samples
        probe.STABILITY_WINDOW = old_window
        engine.measure_iperf3_throughput = old_iperf
