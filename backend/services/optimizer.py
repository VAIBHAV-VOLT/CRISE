"""
Investment Optimizer Service for Cyber Risk Analyzer (Phase 10).
Provides deterministic, explainable budget-constrained decision support.

Answers:
"Given a cybersecurity budget of ₹X, which available security controls should we
invest in to achieve the greatest reduction in enterprise modeled risk?"

Core Principles:
1. Treats non-active controls (Planned / Inactive / Not Implemented) as discrete investment actions.
2. Reuses Phase 4 risk engine formulas (from services.risk_engine) as single mathematical source of truth.
3. Operates on temporary deep copies of processed dataset — NEVER mutates baseline input data.
4. Uses Exact Subset Optimization for N <= 20 candidate controls (guaranteed minimum risk portfolio).
5. Uses Greedy Heuristic Fallback for N > 20 candidate controls.
6. Handles zero budget, negative budget validation, candidate control filtering, and tie-breaking.
"""

import copy
import itertools
from typing import Any, Dict, List, Optional, Tuple

from services.risk_engine import (
    calculate_risk,
    get_risk_level,
)


def validate_optimizer_input(
    processed_data: Dict[str, Any],
    budget: float,
    candidate_control_ids: Optional[List[str]] = None
) -> Tuple[bool, List[str]]:
    """
    Validate optimizer parameters against dataset.
    Returns (is_valid, list_of_error_strings).
    """
    errors: List[str] = []

    if not isinstance(budget, (int, float)):
        errors.append("Budget must be a numeric value.")
    elif budget < 0.0:
        errors.append("Budget must be a non-negative number.")

    if candidate_control_ids is not None:
        if not isinstance(candidate_control_ids, list):
            errors.append("candidate_control_ids must be a list of string control IDs.")
        else:
            # Build set of all control_ids present in processed_data
            all_control_ids = set()
            for a in processed_data.get("assets", []):
                for c in a.get("controls", []):
                    all_control_ids.add(c.get("control_id"))

            for cid in candidate_control_ids:
                if not isinstance(cid, str) or cid not in all_control_ids:
                    errors.append(f"Candidate control ID '{cid}' does not exist in dataset.")

    return (len(errors) == 0), errors


def _get_eligible_controls(
    processed_data: Dict[str, Any],
    candidate_control_ids: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """
    Extract eligible controls (status is not 'Active') from processed_data.
    Filters by candidate_control_ids if supplied.
    """
    candidate_set = set(candidate_control_ids) if candidate_control_ids is not None else None
    eligible: List[Dict[str, Any]] = []

    for a in processed_data.get("assets", []):
        aid = a.get("asset_id")
        aname = a.get("asset", {}).get("asset_name", aid)
        for c in a.get("controls", []):
            cid = c.get("control_id")
            status = str(c.get("implementation_status", "")).strip()
            is_active = status.lower() == "active"

            if not is_active:
                if candidate_set is None or cid in candidate_set:
                    cost = float(c.get("annual_cost", 0.0))
                    eff = float(c.get("effectiveness", 0.0))
                    eligible.append({
                        "control_id": cid,
                        "control_name": c.get("control_name", cid),
                        "asset_id": aid,
                        "asset_name": aname,
                        "annual_cost": cost,
                        "effectiveness": eff,
                        "original_status": status,
                    })

    return eligible


def _evaluate_control_portfolio(
    processed_data: Dict[str, Any],
    selected_control_ids: set
) -> Dict[str, Any]:
    """
    Evaluate Phase 4 enterprise risk when a portfolio of controls is temporarily activated.
    """
    # Create temporary deep copy
    sim_data = copy.deepcopy(processed_data)

    # Activate selected controls
    for a in sim_data.get("assets", []):
        for c in a.get("controls", []):
            if c.get("control_id") in selected_control_ids:
                c["implementation_status"] = "Active"

    return calculate_risk(sim_data)


def optimize_investments(
    processed_data: Dict[str, Any],
    budget: float,
    candidate_control_ids: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Perform deterministic budget-constrained cybersecurity investment optimization.

    Steps:
      1. Validate budget and candidate_control_ids parameters.
      2. Calculate baseline enterprise risk using Phase 4 risk engine.
      3. Identify eligible (non-active) candidate controls.
      4. Handle zero budget / no eligible controls edge cases cleanly.
      5. Select optimal portfolio:
         - Exact Subset Optimization if eligible count <= 20
         - Greedy Heuristic Optimization if eligible count > 20
      6. Calculate budget usage, marginal risk reductions, affected assets, and risk-level transitions.
      7. Return structured optimization payload.
    """
    # 1. Validation
    is_valid, errors = validate_optimizer_input(processed_data, budget, candidate_control_ids)
    if not is_valid:
        return {
            "success": False,
            "errors": errors,
        }

    # 2. Baseline Calculation
    baseline_result = calculate_risk(processed_data)
    ov_base = baseline_result.get("overall_risk", {})
    base_score = ov_base.get("score", 0.0)
    base_level = ov_base.get("level", get_risk_level(base_score))
    asset_base_map = {a["asset_id"]: a for a in baseline_result.get("assets", [])}

    # 3. Identify Eligible Controls
    eligible_controls = _get_eligible_controls(processed_data, candidate_control_ids)

    # Filter out controls whose cost exceeds total budget upfront
    affordable_controls = [c for c in eligible_controls if c["annual_cost"] <= budget]

    if not eligible_controls:
        return {
            "success": True,
            "status": "no_eligible_controls",
            "baseline": {"risk_score": base_score, "risk_level": base_level},
            "optimized": {"risk_score": base_score, "risk_level": base_level},
            "budget": {"available": budget, "used": 0.0, "remaining": budget},
            "impact": {"risk_reduction": 0.0, "percentage_reduction": 0.0},
            "selected_controls": [],
            "affected_assets": [],
            "risk_level_changes": [],
            "algorithm": {"method": "none", "is_optimal": True},
            "explanation": "No eligible unimplemented controls are available for investment optimization.",
        }

    if budget == 0.0 or not affordable_controls:
        return {
            "success": True,
            "status": "no_affordable_controls",
            "baseline": {"risk_score": base_score, "risk_level": base_level},
            "optimized": {"risk_score": base_score, "risk_level": base_level},
            "budget": {"available": budget, "used": 0.0, "remaining": budget},
            "impact": {"risk_reduction": 0.0, "percentage_reduction": 0.0},
            "selected_controls": [],
            "affected_assets": [],
            "risk_level_changes": [],
            "algorithm": {"method": "none", "is_optimal": True},
            "explanation": f"No eligible controls fit within the available budget of ₹{budget:,.2f}.",
        }

    # 5. Run Optimization Algorithm
    N = len(affordable_controls)
    selected_controls_list: List[Dict[str, Any]] = []

    if N <= 20:
        # EXACT SUBSET OPTIMIZATION
        method = "exact_subset"
        is_optimal = True

        best_score = base_score
        best_cost = 0.0
        best_subset: Tuple[Dict[str, Any], ...] = ()

        # Evaluate all subset combinations
        for r in range(1, N + 1):
            for subset in itertools.combinations(affordable_controls, r):
                sub_cost = sum(c["annual_cost"] for c in subset)
                if sub_cost <= budget:
                    selected_cids = {c["control_id"] for c in subset}
                    sub_risk_res = _evaluate_control_portfolio(processed_data, selected_cids)
                    sub_score = sub_risk_res["overall_risk"]["score"]

                    # Selection criteria: lower risk score -> lower cost -> sorted control_ids
                    if sub_score < best_score:
                        best_score = sub_score
                        best_cost = sub_cost
                        best_subset = subset
                    elif abs(sub_score - best_score) < 1e-6:
                        # Tie-break by cost
                        if sub_cost < best_cost:
                            best_score = sub_score
                            best_cost = sub_cost
                            best_subset = subset

        selected_controls_list = list(best_subset)

    else:
        # GREEDY HEURISTIC OPTIMIZATION
        method = "greedy"
        is_optimal = False

        remaining_budget = budget
        current_selected_ids = set()
        pool = copy.deepcopy(affordable_controls)

        while True:
            best_cand = None
            best_cand_score = base_score
            best_cand_reduction = 0.0
            best_cand_ratio = -1.0

            for cand in pool:
                if cand["annual_cost"] > remaining_budget:
                    continue

                cand_set = current_selected_ids | {cand["control_id"]}
                cand_risk_res = _evaluate_control_portfolio(processed_data, cand_set)
                cand_score = cand_risk_res["overall_risk"]["score"]

                # Current portfolio score
                curr_res = _evaluate_control_portfolio(processed_data, current_selected_ids)
                curr_score = curr_res["overall_risk"]["score"]

                cand_reduction = curr_score - cand_score
                cand_ratio = (cand_reduction / cand["annual_cost"]) if cand["annual_cost"] > 0 else cand_reduction

                if cand_reduction > 0.001:
                    # Tie-breaking rules: higher reduction -> higher ratio -> lower cost -> lower control_id
                    if cand_reduction > best_cand_reduction or (
                        abs(cand_reduction - best_cand_reduction) < 1e-6 and cand_ratio > best_cand_ratio
                    ):
                        best_cand = cand
                        best_cand_score = cand_score
                        best_cand_reduction = cand_reduction
                        best_cand_ratio = cand_ratio

            if not best_cand:
                break

            selected_controls_list.append(best_cand)
            current_selected_ids.add(best_cand["control_id"])
            remaining_budget -= best_cand["annual_cost"]
            pool = [c for c in pool if c["control_id"] != best_cand["control_id"]]

    # 6. Final Portfolio Evaluation & Metrics
    final_selected_cids = {c["control_id"] for c in selected_controls_list}
    final_risk_res = _evaluate_control_portfolio(processed_data, final_selected_cids)

    opt_ov = final_risk_res.get("overall_risk", {})
    opt_score = opt_ov.get("score", base_score)
    opt_level = opt_ov.get("level", get_risk_level(opt_score))

    used_budget = round(sum(c["annual_cost"] for c in selected_controls_list), 2)
    remaining_budget = round(max(0.0, budget - used_budget), 2)

    risk_reduction = round(max(0.0, base_score - opt_score), 2)
    if base_score > 0.0:
        pct_reduction = round((risk_reduction / base_score) * 100.0, 2)
    else:
        pct_reduction = 0.0

    # Control-level marginal reduction calculation
    annotated_selected_controls: List[Dict[str, Any]] = []
    for ctrl in selected_controls_list:
        cid = ctrl["control_id"]
        without_cid = final_selected_cids - {cid}
        without_res = _evaluate_control_portfolio(processed_data, without_cid)
        without_score = without_res["overall_risk"]["score"]
        marginal_reduction = round(max(0.0, without_score - opt_score), 2)

        ratio = round(marginal_reduction / ctrl["annual_cost"], 8) if ctrl["annual_cost"] > 0 else 0.0

        annotated_selected_controls.append({
            "control_id": cid,
            "control_name": ctrl["control_name"],
            "asset_id": ctrl["asset_id"],
            "asset_name": ctrl["asset_name"],
            "annual_cost": ctrl["annual_cost"],
            "effectiveness": ctrl["effectiveness"],
            "original_status": ctrl["original_status"],
            "marginal_risk_reduction": marginal_reduction,
            "risk_reduction_per_rupee": ratio,
        })

    # Affected Assets & Risk Level Changes
    opt_asset_map = {a["asset_id"]: a for a in final_risk_res.get("assets", [])}
    affected_assets: List[Dict[str, Any]] = []
    risk_level_changes: List[Dict[str, Any]] = []

    for aid, b_asset in asset_base_map.items():
        o_asset = opt_asset_map.get(aid, {})
        b_score = b_asset.get("risk", {}).get("score", 0.0)
        o_score = o_asset.get("risk", {}).get("score", b_score)
        b_lvl = b_asset.get("risk", {}).get("level", get_risk_level(b_score))
        o_lvl = o_asset.get("risk", {}).get("level", get_risk_level(o_score))
        a_reduction = round(max(0.0, b_score - o_score), 2)

        if a_reduction > 0.0:
            affected_assets.append({
                "asset_id": aid,
                "asset_name": b_asset.get("asset_name", aid),
                "baseline_risk_score": b_score,
                "optimized_risk_score": o_score,
                "risk_reduction": a_reduction,
                "baseline_risk_level": b_lvl,
                "optimized_risk_level": o_lvl,
            })

            if b_lvl != o_lvl:
                risk_level_changes.append({
                    "asset_id": aid,
                    "asset_name": b_asset.get("asset_name", aid),
                    "from": b_lvl,
                    "to": o_lvl,
                })

    # Deterministic Explanation
    if selected_controls_list:
        opt_mode_str = "mathematically optimal" if is_optimal else "greedy heuristic"
        explanation = (
            f"With an available annual budget of ₹{budget:,.2f}, the optimizer ({opt_mode_str}) selects "
            f"{len(selected_controls_list)} control(s) requiring ₹{used_budget:,.2f} (₹{remaining_budget:,.2f} remaining). "
            f"This reduces enterprise modeled risk from {base_score} ({base_level}) to {opt_score} ({opt_level}), "
            f"achieving a risk reduction of {risk_reduction} points ({pct_reduction}%)."
        )
    else:
        explanation = f"No security controls were selected within the budget of ₹{budget:,.2f}."

    return {
        "success": True,
        "status": "optimized",
        "baseline": {
            "risk_score": base_score,
            "risk_level": base_level,
        },
        "optimized": {
            "risk_score": opt_score,
            "risk_level": opt_level,
        },
        "budget": {
            "available": budget,
            "used": used_budget,
            "remaining": remaining_budget,
        },
        "impact": {
            "risk_reduction": risk_reduction,
            "percentage_reduction": pct_reduction,
        },
        "selected_controls": annotated_selected_controls,
        "affected_assets": affected_assets,
        "risk_level_changes": risk_level_changes,
        "algorithm": {
            "method": method,
            "is_optimal": is_optimal,
        },
        "explanation": explanation,
    }
