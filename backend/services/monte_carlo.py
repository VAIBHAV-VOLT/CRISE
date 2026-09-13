"""
Monte Carlo / Uncertainty Risk Simulation Service for Cyber Risk Analyzer (Phase 12).
Provides bounded triangular parameter sampling around baseline risk model inputs.

IMPORTANT:
- Operates strictly on continuous numerical factors (severity, exploitability, control effectiveness, criticality, data sensitivity).
- Continuous factors vary within a ±10% bounded triangular distribution (low = x * 0.9, mode = x, high = x * 1.1), clamped to domain.
- Categorical attributes (internet exposure, IDs, relationships, business values) remain fixed.
- Does NOT model attack probability or likelihood of occurrence.
- Reproducible using a random seed.
"""

from typing import Any, Dict, List, Optional, Tuple
import numpy as np

from services.risk_engine import calculate_risk, get_risk_level


def _sample_triangular(
    rng: np.random.Generator,
    val: float,
    min_bound: float,
    max_bound: float,
    size: int,
    variation: float = 0.10
) -> np.ndarray:
    """
    Sample bounded triangular distribution around val with ±variation range.
    Clamps result within [min_bound, max_bound].
    """
    if val <= 0.0:
        return np.zeros(size, dtype=float)

    low = val * (1.0 - variation)
    mode = val
    high = val * (1.0 + variation)

    if abs(high - low) < 1e-9:
        return np.full(size, val, dtype=float)

    samples = rng.triangular(low, mode, high, size=size)
    return np.clip(samples, min_bound, max_bound)


def run_monte_carlo(
    processed_data: Dict[str, Any],
    baseline_risk_results: Optional[Dict[str, Any]] = None,
    iterations: int = 5000,
    seed: int = 42,
    asset_id: Optional[str] = None
) -> Dict[str, Any]:
    """
    Run Monte Carlo uncertainty risk simulation.

    Args:
        processed_data: Standard process_data() output dict.
        baseline_risk_results: Optional Phase 4 calculate_risk() output dict.
        iterations: Number of Monte Carlo iterations (100 <= N <= 20000).
        seed: Integer seed for reproducible random sampling.
        asset_id: Optional specific asset ID to simulate (simulates enterprise if None).

    Returns:
        JSON-serializable dict conforming to Phase 12 specification.
    """
    # 1. Parameter Validation
    if not isinstance(iterations, int) or iterations < 100 or iterations > 20000:
        raise ValueError("Iterations must be an integer between 100 and 20000.")

    if not isinstance(seed, int):
        try:
            seed = int(seed)
        except (TypeError, ValueError):
            raise ValueError("Seed must be an integer.")

    # Calculate baseline risk if not supplied
    if not baseline_risk_results:
        baseline_risk_results = calculate_risk(processed_data)

    assets_processed = processed_data.get("assets", [])
    proc_asset_map = {str(a.get("asset_id", "")): a for a in assets_processed}

    risk_assets = baseline_risk_results.get("assets", [])
    risk_asset_map = {str(a.get("asset_id", "")): a for a in risk_assets}

    # Verify asset_id existence if specified
    if asset_id:
        asset_id_str = str(asset_id).strip()
        if asset_id_str not in proc_asset_map:
            raise KeyError(f"Asset ID '{asset_id}' does not exist in dataset.")
        target_asset_ids = [asset_id_str]
        scope = "asset"
    else:
        target_asset_ids = sorted(list(proc_asset_map.keys()))
        scope = "enterprise"

    # Handle empty dataset edge case
    if not target_asset_ids:
        baseline_score = 0.0
        baseline_level = "LOW"
        zero_stats = {
            "mean": 0.0, "median": 0.0, "std_dev": 0.0,
            "min": 0.0, "max": 0.0, "p5": 0.0, "p25": 0.0, "p75": 0.0, "p95": 0.0
        }
        zero_dist = {
            "LOW": {"count": iterations, "percentage": 100.0},
            "MEDIUM": {"count": 0, "percentage": 0.0},
            "HIGH": {"count": 0, "percentage": 0.0},
            "CRITICAL": {"count": 0, "percentage": 0.0},
        }
        return {
            "scope": scope,
            "asset_id": asset_id if scope == "asset" else None,
            "iterations": iterations,
            "seed": seed,
            "baseline": {"risk_score": baseline_score, "risk_level": baseline_level},
            "simulation": zero_stats,
            "risk_level_distribution": zero_dist,
            "uncertainty_band": "LOW",
            "explanation": f"The baseline {scope} risk is 0.00 (LOW). No assets present for uncertainty simulation.",
        }

    # 2. Baseline Resolution
    if scope == "asset":
        target_id = target_asset_ids[0]
        r_item = risk_asset_map.get(target_id, {}).get("risk", {})
        baseline_score = float(r_item.get("score", 0.0))
        baseline_level = str(r_item.get("level", get_risk_level(baseline_score)))
    else:
        ov = baseline_risk_results.get("overall_risk", {})
        baseline_score = float(ov.get("score", 0.0))
        baseline_level = str(ov.get("level", get_risk_level(baseline_score)))

    # 3. Vectorized Monte Carlo Random Sampling
    rng = np.random.default_rng(seed)

    # Dictionary to hold simulated asset risk score arrays (shape: (iterations,))
    simulated_asset_scores: Dict[str, np.ndarray] = {}
    asset_business_values: Dict[str, float] = {}

    for aid in target_asset_ids:
        p_item = proc_asset_map[aid]
        asset_info = p_item.get("asset", {})
        bv = float(asset_info.get("business_value", 0.0))
        asset_business_values[aid] = max(0.0, bv)

        # Base factors
        crit_raw = float(asset_info.get("criticality", 0.0))
        sens_raw = float(asset_info.get("data_sensitivity", 0.0))
        internet_raw = asset_info.get("internet_exposed", False)
        internet_exposed = str(internet_raw).lower() in ("true", "1", "yes")
        internet_factor = 1.0 if internet_exposed else 0.0

        crit_samples = _sample_triangular(rng, crit_raw, 0.0, 5.0, iterations)
        sens_samples = _sample_triangular(rng, sens_raw, 0.0, 5.0, iterations)

        crit_factors = crit_samples / 5.0
        sens_factors = sens_samples / 5.0

        # Vulnerabilities aggregation
        vulns = p_item.get("vulnerabilities", [])
        prod_vuln_compl = np.ones(iterations, dtype=float)

        for v in vulns:
            sev = float(v.get("severity", 0.0))
            exp = float(v.get("exploitability", 0.0))

            sev_samples = _sample_triangular(rng, sev, 0.0, 10.0, iterations)
            exp_samples = _sample_triangular(rng, exp, 0.0, 1.0, iterations)

            v_exposure = (sev_samples / 10.0) * exp_samples
            v_exposure = np.clip(v_exposure, 0.0, 1.0)
            prod_vuln_compl *= (1.0 - v_exposure)

        if vulns:
            combined_vuln_exposure = np.clip(1.0 - prod_vuln_compl, 0.0, 1.0)
        else:
            combined_vuln_exposure = np.zeros(iterations, dtype=float)

        # Controls aggregation (Active controls only)
        controls = p_item.get("controls", [])
        active_controls = [
            c for c in controls
            if str(c.get("implementation_status", "")).strip().lower() in ("active", "implemented", "1", "true")
        ]
        prod_ctrl_compl = np.ones(iterations, dtype=float)

        for c in active_controls:
            eff = float(c.get("effectiveness", 0.0))
            eff_samples = _sample_triangular(rng, eff, 0.0, 1.0, iterations)
            prod_ctrl_compl *= (1.0 - eff_samples)

        if active_controls:
            combined_ctrl_eff = np.clip(1.0 - prod_ctrl_compl, 0.0, 1.0)
        else:
            combined_ctrl_eff = np.zeros(iterations, dtype=float)

        remaining_exposure = 1.0 - combined_ctrl_eff

        base_exposure = (
            0.50 * combined_vuln_exposure +
            0.20 * crit_factors +
            0.15 * sens_factors +
            0.15 * internet_factor
        )

        risk_factor = base_exposure * remaining_exposure
        asset_scores = np.clip(risk_factor * 100.0, 0.0, 100.0)
        simulated_asset_scores[aid] = asset_scores

    # 4. Enterprise / Asset Score Aggregation
    if scope == "asset":
        final_simulated_scores = simulated_asset_scores[target_asset_ids[0]]
    else:
        total_bv = sum(asset_business_values.values())
        if total_bv > 0.0:
            weighted_sum = np.zeros(iterations, dtype=float)
            for aid in target_asset_ids:
                weighted_sum += simulated_asset_scores[aid] * asset_business_values[aid]
            final_simulated_scores = weighted_sum / total_bv
        else:
            # Arithmetic average fallback
            sum_scores = np.zeros(iterations, dtype=float)
            for aid in target_asset_ids:
                sum_scores += simulated_asset_scores[aid]
            final_simulated_scores = sum_scores / float(len(target_asset_ids))

    final_simulated_scores = np.clip(final_simulated_scores, 0.0, 100.0)

    # 5. Compute Statistics
    mean_val = round(float(np.mean(final_simulated_scores)), 2)
    median_val = round(float(np.median(final_simulated_scores)), 2)
    std_val = round(float(np.std(final_simulated_scores)), 2)
    min_val = round(float(np.min(final_simulated_scores)), 2)
    max_val = round(float(np.max(final_simulated_scores)), 2)
    p5_val = round(float(np.percentile(final_simulated_scores, 5)), 2)
    p25_val = round(float(np.percentile(final_simulated_scores, 25)), 2)
    p75_val = round(float(np.percentile(final_simulated_scores, 75)), 2)
    p95_val = round(float(np.percentile(final_simulated_scores, 95)), 2)

    simulation_stats = {
        "mean": mean_val,
        "median": median_val,
        "std_dev": std_val,
        "min": min_val,
        "max": max_val,
        "p5": p5_val,
        "p25": p25_val,
        "p75": p75_val,
        "p95": p95_val,
    }

    # 6. Compute Risk Level Distribution
    c_low = int(np.sum(final_simulated_scores <= 25.0))
    c_med = int(np.sum((final_simulated_scores > 25.0) & (final_simulated_scores <= 50.0)))
    c_high = int(np.sum((final_simulated_scores > 50.0) & (final_simulated_scores <= 75.0)))
    c_crit = int(np.sum(final_simulated_scores > 75.0))

    risk_level_dist = {
        "LOW": {
            "count": c_low,
            "percentage": round((c_low / iterations) * 100.0, 2),
        },
        "MEDIUM": {
            "count": c_med,
            "percentage": round((c_med / iterations) * 100.0, 2),
        },
        "HIGH": {
            "count": c_high,
            "percentage": round((c_high / iterations) * 100.0, 2),
        },
        "CRITICAL": {
            "count": c_crit,
            "percentage": round((c_crit / iterations) * 100.0, 2),
        },
    }

    # 7. Uncertainty Band & Explanation
    diff = p95_val - p5_val
    if diff < 10.0:
        uncertainty_band = "LOW"
    elif diff < 25.0:
        uncertainty_band = "MODERATE"
    else:
        uncertainty_band = "HIGH"

    scope_name = f"asset '{target_asset_ids[0]}'" if scope == "asset" else "enterprise"
    explanation = (
        f"The baseline {scope_name} risk is {baseline_score:.2f} ({baseline_level}). "
        f"Under the modeled ±10% uncertainty in continuous risk inputs, the median simulated risk is {median_val:.2f} "
        f"and the 5th–95th percentile range is {p5_val:.2f}–{p95_val:.2f}. "
        f"This indicates {uncertainty_band.lower()} variation around the baseline rather than a prediction of attack probability."
    )

    result = {
        "scope": scope,
        "iterations": iterations,
        "seed": seed,
        "baseline": {
            "risk_score": baseline_score,
            "risk_level": baseline_level,
        },
        "simulation": simulation_stats,
        "risk_level_distribution": risk_level_dist,
        "uncertainty_band": uncertainty_band,
        "explanation": explanation,
    }

    if scope == "asset":
        result["asset_id"] = target_asset_ids[0]

    return result
