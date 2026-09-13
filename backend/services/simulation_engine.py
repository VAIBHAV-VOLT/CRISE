"""
Simulation Engine Service for Cyber Risk Analyzer (Phase 9).
Provides deterministic, explainable what-if scenario simulations for cybersecurity risk.

Core Features:
1. Operates on temporary deep copies of processed dataset — NEVER mutates original input data.
2. Reuses Phase 4 risk engine formulas (from services.risk_engine) as the mathematical source of truth.
3. Supports 4 scenario modification types:
   - Control effectiveness change (0.0 <= effectiveness <= 1.0)
   - Control activation/deactivation (active boolean mapped to implementation_status)
   - Vulnerability remediation (exposure_factor = 0.0)
   - Internet exposure change (internet_exposed boolean)
4. Supports asset-level (specific asset_id) and enterprise-level (asset_id = None) simulations.
5. Performs strict input validation (validates asset_id, control_id, vulnerability_id ownership and bounds).
6. Computes baseline, scenario, delta metrics, and deterministic rule-based impact explanations.
"""

import copy
from typing import Any, Dict, List, Optional, Tuple

from services.risk_engine import (
    calculate_asset_risk,
    calculate_risk,
    get_risk_level,
)


def validate_scenario_input(
    processed_data: Dict[str, Any],
    scenario_input: Dict[str, Any]
) -> Tuple[bool, List[str]]:
    """
    Validate scenario input against the supplied processed dataset.
    Returns (is_valid, list_of_error_strings).
    """
    errors: List[str] = []
    if not isinstance(scenario_input, dict):
        return False, ["Scenario input must be a JSON object/dict."]

    raw_assets = processed_data.get("assets", [])
    assets_map = {a.get("asset_id"): a for a in raw_assets}

    asset_id = scenario_input.get("asset_id")

    # If specific asset_id is provided, verify it exists
    if asset_id is not None and str(asset_id).strip() != "":
        asset_id_str = str(asset_id).strip()
        if asset_id_str not in assets_map:
            errors.append(f"Asset ID '{asset_id_str}' does not exist in dataset.")
            return False, errors
        target_assets = [assets_map[asset_id_str]]
    else:
        target_assets = raw_assets

    # Validate Control Changes
    control_changes = scenario_input.get("control_changes", [])
    if not isinstance(control_changes, list):
        errors.append("control_changes must be a list.")
    else:
        # Build map of valid control_ids for target assets
        valid_control_ids = {}
        for a in target_assets:
            for c in a.get("controls", []):
                valid_control_ids[c.get("control_id")] = a.get("asset_id")

        for idx, cc in enumerate(control_changes):
            if not isinstance(cc, dict):
                errors.append(f"control_changes[{idx}] must be an object.")
                continue
            cid = cc.get("control_id")
            if not cid or cid not in valid_control_ids:
                errors.append(f"Control ID '{cid}' does not exist or does not belong to target asset(s).")
            if "effectiveness" in cc:
                eff = cc["effectiveness"]
                if not isinstance(eff, (int, float)) or eff < 0.0 or eff > 1.0:
                    errors.append(f"Invalid effectiveness '{eff}' for control '{cid}'. Must be between 0.0 and 1.0.")
            if "active" in cc and not isinstance(cc["active"], bool):
                errors.append(f"Invalid active status for control '{cid}'. Must be a boolean.")

    # Validate Remediated Vulnerabilities
    remediated_vulns = scenario_input.get("remediated_vulnerabilities", [])
    if not isinstance(remediated_vulns, list):
        errors.append("remediated_vulnerabilities must be a list.")
    else:
        valid_vuln_ids = {}
        for a in target_assets:
            for v in a.get("vulnerabilities", []):
                valid_vuln_ids[v.get("vulnerability_id")] = a.get("asset_id")

        for idx, vid in enumerate(remediated_vulns):
            if not isinstance(vid, str) or vid not in valid_vuln_ids:
                errors.append(f"Vulnerability ID '{vid}' does not exist or does not belong to target asset(s).")

    # Validate Internet Exposed
    if "internet_exposed" in scenario_input and scenario_input["internet_exposed"] is not None:
        ie = scenario_input["internet_exposed"]
        if not isinstance(ie, bool):
            errors.append("internet_exposed must be a boolean.")

    return (len(errors) == 0), errors


def apply_scenario_modifications(
    processed_data: Dict[str, Any],
    scenario_input: Dict[str, Any]
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Apply scenario modifications to a TEMPORARY DEEP COPY of processed_data.
    Returns (modified_processed_data, metadata_of_applied_changes).
    """
    # 1. Create a deep copy to ensure complete data integrity
    scenario_data = copy.deepcopy(processed_data)

    asset_id = scenario_input.get("asset_id")
    target_aid = str(asset_id).strip() if asset_id is not None and str(asset_id).strip() != "" else None

    control_changes = {cc["control_id"]: cc for cc in scenario_input.get("control_changes", []) if isinstance(cc, dict) and "control_id" in cc}
    remediated_vuln_set = set(scenario_input.get("remediated_vulnerabilities", []))
    internet_exposed_override = scenario_input.get("internet_exposed")

    applied_controls: List[Dict[str, Any]] = []
    applied_remediations: List[str] = []
    internet_exposure_changed = False

    for asset_profile in scenario_data.get("assets", []):
        aid = asset_profile.get("asset_id")
        if target_aid is not None and aid != target_aid:
            continue

        # A & B. Control Effectiveness and Active/Inactive Changes
        for ctrl in asset_profile.get("controls", []):
            cid = ctrl.get("control_id")
            if cid in control_changes:
                cc = control_changes[cid]
                if "effectiveness" in cc:
                    ctrl["effectiveness"] = float(cc["effectiveness"])
                if "active" in cc:
                    ctrl["implementation_status"] = "Active" if cc["active"] else "Inactive"
                applied_controls.append({
                    "control_id": cid,
                    "control_name": ctrl.get("control_name", cid),
                    "effectiveness": ctrl.get("effectiveness"),
                    "status": ctrl.get("implementation_status"),
                })

        # C. Vulnerability Remediation
        if remediated_vuln_set:
            remaining_vulns = []
            for vuln in asset_profile.get("vulnerabilities", []):
                vid = vuln.get("vulnerability_id")
                if vid in remediated_vuln_set:
                    applied_remediations.append(vid)
                else:
                    remaining_vulns.append(vuln)
            asset_profile["vulnerabilities"] = remaining_vulns

        # D. Internet Exposure Change
        if internet_exposed_override is not None and isinstance(internet_exposed_override, bool):
            asset_info = asset_profile.get("asset", {})
            orig_ie = asset_info.get("internet_exposed", False)
            if orig_ie != internet_exposed_override:
                asset_info["internet_exposed"] = internet_exposed_override
                internet_exposure_changed = True

    applied_summary = {
        "controls": applied_controls,
        "remediated_vulnerabilities": applied_remediations,
        "internet_exposure_changed": internet_exposure_changed,
    }

    return scenario_data, applied_summary


def generate_impact_explanation(
    baseline_score: float,
    scenario_score: float,
    baseline_level: str,
    scenario_level: str,
    changes: Dict[str, Any],
    asset_name: str = "Enterprise"
) -> str:
    """
    Generate a clear, deterministic, non-AI impact explanation.
    """
    diff = round(scenario_score - baseline_score, 2)
    reduction = round(-diff, 2)

    explanations: List[str] = []

    rem_vulns = changes.get("remediated_vulnerabilities", [])
    if rem_vulns:
        explanations.append(f"Remediating {len(rem_vulns)} vulnerability(ies) ({', '.join(rem_vulns)}) reduces vulnerability exposure.")

    controls = changes.get("controls", [])
    if controls:
        ctrl_names = [c["control_id"] for c in controls]
        explanations.append(f"Updating control(s) ({', '.join(ctrl_names)}) mitigates remaining asset exposure.")

    if changes.get("internet_exposure_changed"):
        explanations.append("Modifying internet exposure alters the intrinsic asset exposure factor.")

    if not explanations:
        return f"No scenario changes applied. Modeled risk score remains {baseline_score} ({baseline_level})."

    details = " ".join(explanations)
    if reduction > 0:
        msg = f"{details} This lowers the modeled risk score of {asset_name} from {baseline_score} to {scenario_score} (risk reduction: {reduction} pts)."
    elif reduction < 0:
        msg = f"{details} This increases the modeled risk score of {asset_name} from {baseline_score} to {scenario_score} (risk increase: {-reduction} pts)."
    else:
        msg = f"{details} Modeled risk score of {asset_name} remains unchanged at {baseline_score}."

    if baseline_level != scenario_level:
        msg += f" Risk level shifts from {baseline_level} to {scenario_level}."

    return msg


def simulate_scenario(
    processed_data: Dict[str, Any],
    scenario_input: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Perform a deterministic what-if risk simulation.

    Steps:
      1. Validate input structure and parameters against dataset.
      2. Calculate baseline risk using Phase 4 formulas.
      3. Deep-copy data and apply scenario modifications.
      4. Recalculate scenario risk using Phase 4 formulas.
      5. Compute delta metrics and impact explanation.
      6. Return clean structured result.
    """
    # 1. Validation
    is_valid, errors = validate_scenario_input(processed_data, scenario_input)
    if not is_valid:
        return {
            "success": False,
            "errors": errors,
        }

    asset_id = scenario_input.get("asset_id")
    target_aid = str(asset_id).strip() if asset_id is not None and str(asset_id).strip() != "" else None

    # 2. Baseline Calculation
    baseline_full_result = calculate_risk(processed_data)

    if target_aid is not None:
        # Asset-level baseline
        asset_baselines = {a["asset_id"]: a for a in baseline_full_result.get("assets", [])}
        target_base = asset_baselines.get(target_aid, {})
        base_score = target_base.get("risk", {}).get("score", 0.0)
        base_level = target_base.get("risk", {}).get("level", get_risk_level(base_score))
        asset_name = target_base.get("asset_name", target_aid)
        baseline_summary = {
            "asset_id": target_aid,
            "asset_name": asset_name,
            "risk_score": base_score,
            "risk_level": base_level,
        }
    else:
        # Enterprise-level baseline
        ov = baseline_full_result.get("overall_risk", {})
        base_score = ov.get("score", 0.0)
        base_level = ov.get("level", get_risk_level(base_score))
        asset_name = "Enterprise"
        baseline_summary = {
            "asset_id": None,
            "asset_name": "Enterprise",
            "risk_score": base_score,
            "risk_level": base_level,
        }

    # 3. Apply modifications to deep copy
    scenario_data, applied_changes = apply_scenario_modifications(processed_data, scenario_input)

    # 4. Scenario Calculation (Reusing Phase 4 risk engine)
    scenario_full_result = calculate_risk(scenario_data)

    if target_aid is not None:
        asset_scenarios = {a["asset_id"]: a for a in scenario_full_result.get("assets", [])}
        target_scen = asset_scenarios.get(target_aid, {})
        scen_score = target_scen.get("risk", {}).get("score", 0.0)
        scen_level = target_scen.get("risk", {}).get("level", get_risk_level(scen_score))
        scenario_summary = {
            "asset_id": target_aid,
            "asset_name": asset_name,
            "risk_score": scen_score,
            "risk_level": scen_level,
        }
    else:
        ov_scen = scenario_full_result.get("overall_risk", {})
        scen_score = ov_scen.get("score", 0.0)
        scen_level = ov_scen.get("level", get_risk_level(scen_score))
        scenario_summary = {
            "asset_id": None,
            "asset_name": "Enterprise",
            "risk_score": scen_score,
            "risk_level": scen_level,
        }

    # 5. Delta Calculations
    risk_score_change = round(scen_score - base_score, 2)
    risk_reduction = round(-risk_score_change, 2)

    if base_score > 0.0:
        percentage_change = round(((scen_score - base_score) / base_score) * 100.0, 2)
    else:
        percentage_change = 0.0

    delta_summary = {
        "risk_score_change": risk_score_change,
        "risk_reduction": risk_reduction,
        "percentage_change": percentage_change,
    }

    # 6. Explanation
    explanation = generate_impact_explanation(
        baseline_score=base_score,
        scenario_score=scen_score,
        baseline_level=base_level,
        scenario_level=scen_level,
        changes=applied_changes,
        asset_name=asset_name,
    )

    return {
        "success": True,
        "baseline": baseline_summary,
        "scenario": scenario_summary,
        "delta": delta_summary,
        "changes_applied": applied_changes,
        "explanation": explanation,
    }
