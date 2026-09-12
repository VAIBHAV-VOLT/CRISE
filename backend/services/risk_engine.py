"""
Cyber Risk Engine Service for Cyber Risk Analyzer.
Implements deterministic, explainable modeled risk scoring for assets and the enterprise.

All calculations follow the CRISE Risk Model specification:
- Vulnerability Exposure: (severity / 10.0) * exploitability
- Aggregate Vulnerability Exposure: 1 - product(1 - vulnerability_exposure)
- Control Effectiveness: Diminishing returns combination: 1 - product(1 - effectiveness) for Active controls only.
  (Planned controls do NOT reduce current risk; they are preserved for What-If and optimization).
- Remaining Exposure: 1 - combined_control_effectiveness
- Asset Criticality Factor: criticality / 5.0
- Data Sensitivity Factor: data_sensitivity / 5.0
- Internet Exposure Factor: 1.0 if internet_exposed else 0.0
- Base Exposure: 0.50 * vuln_exp + 0.20 * crit + 0.15 * sens + 0.15 * internet
- Modeled Risk Factor: base_exposure * remaining_exposure
- Modeled Risk Score: clamp(risk_factor * 100, 0, 100) rounded to 2 decimal places.
- Risk Levels:
    0 <= score <= 25: LOW
    25 < score <= 50: MEDIUM
    50 < score <= 75: HIGH
    75 < score <= 100: CRITICAL
- Enterprise Risk: Business-value weighted risk score, with arithmetic average fallback if total business value is 0.

DISCLAIMER:
This prototype uses a transparent modeled risk score for comparative prioritization.
It is NOT a certified cybersecurity rating, probability of attack, or guarantee of financial loss.
"""

from typing import Any, Dict, List
import math


def get_risk_level(score: float) -> str:
    """
    Map a numeric risk score (0 to 100) to a discrete, non-overlapping risk level.
    0 <= score <= 25  -> LOW
    25 < score <= 50  -> MEDIUM
    50 < score <= 75  -> HIGH
    75 < score <= 100 -> CRITICAL
    """
    if score <= 25.0:
        return "LOW"
    elif score <= 50.0:
        return "MEDIUM"
    elif score <= 75.0:
        return "HIGH"
    else:
        return "CRITICAL"


def calculate_vulnerability_exposure(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate modeled exposure for a single vulnerability:
      severity_factor = severity / 10.0
      vulnerability_exposure = severity_factor * exploitability
    This yields a normalized exposure factor between 0.0 and 1.0.
    """
    sev = float(vuln.get("severity", 0.0))
    exp = float(vuln.get("exploitability", 0.0))
    sev_factor = sev / 10.0
    exposure_factor = round(sev_factor * exp, 4)
    return {
        "vulnerability_id": vuln.get("vulnerability_id", ""),
        "vulnerability_name": vuln.get("vulnerability_name", ""),
        "severity": sev,
        "exploitability": exp,
        "exposure_factor": exposure_factor,
    }


def calculate_asset_risk(asset_profile: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate modeled risk for an individual asset profile.

    Formula:
      combined_vuln_exposure = 1 - product(1 - vuln_exposure)  [0 if no vulns]
      combined_control_effectiveness = 1 - product(1 - effectiveness)  [Active controls only]
      remaining_exposure = 1 - combined_control_effectiveness
      criticality_factor = criticality / 5.0
      sensitivity_factor = data_sensitivity / 5.0
      internet_factor = 1.0 if internet_exposed else 0.0
      base_exposure = 0.50 * combined_vuln_exposure + 0.20 * criticality_factor + 0.15 * sensitivity_factor + 0.15 * internet_factor
      risk_factor = base_exposure * remaining_exposure
      risk_score = round(clamp(risk_factor * 100, 0, 100), 2)
    """
    asset_info = asset_profile.get("asset", {})
    asset_id = asset_profile.get("asset_id", "")

    # 1. Vulnerability-level exposure & aggregate combination
    vuln_results: List[Dict[str, Any]] = []
    prod_vuln_compl = 1.0
    vulns = asset_profile.get("vulnerabilities", [])
    for v in vulns:
        v_res = calculate_vulnerability_exposure(v)
        vuln_results.append(v_res)
        prod_vuln_compl *= (1.0 - v_res["exposure_factor"])

    if vuln_results:
        combined_vuln_exposure = round(max(0.0, min(1.0, 1.0 - prod_vuln_compl)), 4)
    else:
        combined_vuln_exposure = 0.0

    # 2. Control-level results & aggregate effectiveness
    # MODELING ASSUMPTION:
    # Overlapping defense-in-depth controls follow diminishing returns:
    # combined_control_effectiveness = 1 - product(1 - effectiveness)
    # Only controls with status 'Active' (case-insensitive) reduce current risk.
    # Planned controls are preserved but do not mitigate current risk.
    control_results: List[Dict[str, Any]] = []
    prod_ctrl_compl = 1.0
    has_active_controls = False
    controls = asset_profile.get("controls", [])
    for c in controls:
        eff = float(c.get("effectiveness", 0.0))
        status = str(c.get("implementation_status", "")).strip()
        is_active = status.lower() == "active"
        control_results.append({
            "control_id": c.get("control_id", ""),
            "control_name": c.get("control_name", ""),
            "effectiveness": eff,
            "status": status,
            "counts_toward_current_risk": is_active,
        })
        if is_active:
            has_active_controls = True
            prod_ctrl_compl *= (1.0 - eff)

    if has_active_controls:
        combined_control_effectiveness = round(max(0.0, min(1.0, 1.0 - prod_ctrl_compl)), 4)
    else:
        combined_control_effectiveness = 0.0

    remaining_exposure = round(max(0.0, min(1.0, 1.0 - combined_control_effectiveness)), 4)

    # 3. Asset Importance Factors
    crit = float(asset_info.get("criticality", 1))
    crit_factor = round(crit / 5.0, 4)

    sens = float(asset_info.get("data_sensitivity", 1))
    sens_factor = round(sens / 5.0, 4)

    internet_exposed = bool(asset_info.get("internet_exposed", False))
    internet_factor = 1.0 if internet_exposed else 0.0

    # 4. Modeled Risk Factor
    # Base exposure combines intrinsic drivers:
    # 50% vulnerability exposure + 20% criticality + 15% data sensitivity + 15% internet exposure
    base_exposure = (
        0.50 * combined_vuln_exposure
        + 0.20 * crit_factor
        + 0.15 * sens_factor
        + 0.15 * internet_factor
    )

    # Controls mitigate the base exposure
    risk_factor = base_exposure * remaining_exposure
    risk_score = round(max(0.0, min(100.0, risk_factor * 100.0)), 2)
    risk_level = get_risk_level(risk_score)

    # 5. Deterministic, Rule-Based Explanation (No LLM)
    explanation: List[str] = []

    # Criticality
    if crit >= 4:
        explanation.append(f"Asset has high criticality (level {int(crit)}/5).")
    elif crit >= 3:
        explanation.append(f"Asset has moderate criticality (level {int(crit)}/5).")
    else:
        explanation.append(f"Asset has low operational criticality (level {int(crit)}/5).")

    # Vulnerability exposure
    if vuln_results:
        max_sev = max(v["severity"] for v in vuln_results)
        if max_sev >= 7.0:
            explanation.append(f"Asset contains high-severity vulnerabilities (highest severity: {max_sev}).")
        else:
            explanation.append(f"Asset contains {len(vuln_results)} vulnerabilities (highest severity: {max_sev}).")
    else:
        explanation.append("Asset has no recorded vulnerabilities.")

    # Internet exposure
    if internet_exposed:
        explanation.append("Asset is exposed to the internet.")
    else:
        explanation.append("Asset is internal and not directly exposed to the internet.")

    # Controls
    if combined_control_effectiveness > 0.0:
        pct = round(combined_control_effectiveness * 100, 1)
        rem_pct = round(remaining_exposure * 100, 1)
        explanation.append(f"Existing active controls reduce exposure by {pct}% (remaining exposure: {rem_pct}%).")
    else:
        explanation.append("No active security controls in place to mitigate exposure.")

    return {
        "asset_id": asset_id,
        "asset_name": asset_info.get("asset_name", ""),
        "asset_type": asset_info.get("asset_type", ""),
        "department": asset_info.get("department", ""),
        "business_value": float(asset_info.get("business_value", 0.0)),
        "criticality": int(crit),
        "internet_exposed": internet_exposed,
        "data_sensitivity": int(sens),
        "risk": {
            "score": risk_score,
            "level": risk_level,
            "factors": {
                "vulnerability_exposure": combined_vuln_exposure,
                "criticality_factor": crit_factor,
                "sensitivity_factor": sens_factor,
                "internet_exposure_factor": internet_factor,
                "control_effectiveness": combined_control_effectiveness,
                "remaining_exposure": remaining_exposure,
            },
            "explanation": explanation,
        },
        "vulnerabilities": vuln_results,
        "controls": control_results,
        "incidents": asset_profile.get("incidents", []),
    }


def calculate_risk(processed_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate enterprise-level modeled risk across all assets.

    Computes:
      - Individual asset risk profiles
      - Business-value weighted enterprise risk score:
          overall_risk = sum(asset_risk * business_value) / sum(business_value)
          Fallback: simple arithmetic mean if total business value is 0.
      - Risk distribution counts (critical, high, medium, low)
      - Top risk assets ranked by risk score descending (up to 10)
    """
    raw_assets = processed_data.get("assets", [])
    scored_assets = [calculate_asset_risk(a) for a in raw_assets]

    # Enterprise business-value weighted risk
    total_bv = sum(a["business_value"] for a in scored_assets)
    if total_bv > 0.0:
        weighted_risk = sum(a["risk"]["score"] * a["business_value"] for a in scored_assets)
        overall_score = round(max(0.0, min(100.0, weighted_risk / total_bv)), 2)
    else:
        # Documented fallback: arithmetic mean when total business value is 0
        if scored_assets:
            overall_score = round(max(0.0, min(100.0, sum(a["risk"]["score"] for a in scored_assets) / len(scored_assets))), 2)
        else:
            overall_score = 0.0

    overall_level = get_risk_level(overall_score)

    # Risk distribution
    risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in scored_assets:
        lvl = a["risk"]["level"].lower()
        if lvl in risk_distribution:
            risk_distribution[lvl] += 1

    # Top risk assets (top 10 sorted by risk score descending)
    sorted_assets = sorted(scored_assets, key=lambda a: a["risk"]["score"], reverse=True)
    top_risk_assets = [
        {
            "asset_id": a["asset_id"],
            "asset_name": a["asset_name"],
            "risk_score": a["risk"]["score"],
            "risk_level": a["risk"]["level"],
        }
        for a in sorted_assets[:10]
    ]

    return {
        "success": True,
        "overall_risk": {
            "score": overall_score,
            "level": overall_level,
        },
        "risk_distribution": risk_distribution,
        "top_risk_assets": top_risk_assets,
        "assets": scored_assets,
    }
