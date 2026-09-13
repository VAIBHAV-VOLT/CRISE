"""
CRISE — AI Context Service
==========================
Constructs compact, relevant, structured JSON representations of CRISE findings
to pass as background context to the AI Security Analyst.

CRITICAL RULES:
1. Context must come strictly from structured CRISE engine outputs (Phases 4–14).
2. Raw CSV files are never read or dumped into context.
3. Keeps payload concise while expanding specific items if referenced in user's question.
"""

from typing import Dict, Any, Optional, List


def build_ai_context(analysis_data: Dict[str, Any], question: Optional[str] = None) -> Dict[str, Any]:
    """
    Construct a compact, structured representation of CRISE results.
    """
    if not isinstance(analysis_data, dict):
        analysis_data = {}

    question_lower = (question or "").lower()

    # 1. Overall & Enterprise Risk Context
    risk_raw = analysis_data.get("risk") or {}
    overall_risk = analysis_data.get("overall_risk") or risk_raw.get("overall_risk") or {}
    top_assets_raw = analysis_data.get("top_risk_assets") or risk_raw.get("top_risk_assets") or []

    top_assets_summary = [
        {
            "asset_id": a.get("asset_id"),
            "asset_name": a.get("asset_name"),
            "risk_score": round(float(a.get("risk_score", 0.0)), 1),
            "risk_level": a.get("risk_level"),
            "business_value": a.get("business_value")
        } for a in top_assets_raw[:5]
    ]

    context = {
        "risk": {
            "overall_score": round(float(overall_risk.get("score", 0.0)), 2),
            "overall_level": overall_risk.get("level", "UNKNOWN"),
            "risk_distribution": risk_raw.get("risk_distribution", {}),
            "top_risk_assets": top_assets_summary
        }
    }

    # 2. Financial Risk Context
    fin_raw = analysis_data.get("financial") or {}
    fin_summary = fin_raw.get("financial_summary") or {}
    if fin_summary:
        context["financial"] = {
            "historical_annualized_loss": fin_summary.get("historical_annualized_loss") or fin_summary.get("total_historical_annualized_loss") or 0.0,
            "risk_based_business_exposure": fin_summary.get("risk_based_business_exposure") or fin_summary.get("total_risk_based_business_exposure") or 0.0
        }

    # 3. Threat Engine Context
    threats_raw = analysis_data.get("threats") or {}
    scenarios = threats_raw.get("scenarios") or []
    if scenarios:
        context["threats"] = {
            "scenario_count": threats_raw.get("scenario_count", len(scenarios)),
            "top_scenarios": [
                {
                    "scenario_id": s.get("scenario_id"),
                    "title": s.get("title"),
                    "threat_type": s.get("threat_type"),
                    "modeled_exposure": s.get("modeled_exposure"),
                    "risk_level": s.get("scenario_risk_level")
                } for s in scenarios[:5]
            ]
        }

    # 4. Intelligence (Vulnerabilities & Assets) Context
    intel_raw = analysis_data.get("intelligence") or {}
    vulns_intel = intel_raw.get("vulnerabilities") or []
    if vulns_intel:
        context["vulnerabilities"] = [
            {
                "vulnerability_id": v.get("vulnerability_id"),
                "vulnerability_name": v.get("vulnerability_name"),
                "severity": v.get("severity"),
                "affected_assets": v.get("affected_assets_count"),
                "risk_contribution": v.get("risk_contribution_percentage")
            } for v in vulns_intel[:5]
        ]

    # 5. Cybersecurity Recommendations Context
    recs_raw = analysis_data.get("recommendations") or {}
    rec_list = recs_raw.get("recommendations") or []
    if rec_list:
        context["recommendations"] = [
            {
                "recommendation_id": r.get("recommendation_id"),
                "priority": r.get("priority"),
                "title": r.get("title"),
                "affected_asset": r.get("asset_name") or r.get("asset_id"),
                "action": r.get("recommended_action")
            } for r in rec_list[:5]
        ]

    # 6. Monte Carlo Uncertainty Context
    mc_raw = analysis_data.get("monte_carlo") or {}
    if mc_raw.get("status") == "success" or "stats" in mc_raw:
        mc_stats = mc_raw.get("stats") or {}
        context["monte_carlo"] = {
            "median_risk": mc_stats.get("median"),
            "p5": mc_stats.get("p5"),
            "p95": mc_stats.get("p95"),
            "uncertainty_band": mc_raw.get("uncertainty_band"),
            "explanation": mc_raw.get("explanation")
        }

    # 7. MITRE ATT&CK Context
    mitre_raw = analysis_data.get("mitre") or {}
    mitre_sum = mitre_raw.get("summary") or {}
    if mitre_sum:
        context["mitre"] = {
            "mapped_incidents": mitre_sum.get("mapped_incidents"),
            "unmapped_incidents": mitre_sum.get("unmapped_incidents"),
            "coverage_percentage": mitre_sum.get("mapping_coverage_percentage"),
            "unique_tactics": mitre_sum.get("unique_tactics"),
            "unique_techniques": mitre_sum.get("unique_techniques")
        }

    # 8. Compliance & Framework Mapping Context
    comp_raw = analysis_data.get("compliance") or {}
    comp_frameworks = comp_raw.get("frameworks") or []
    comp_summary = comp_raw.get("summary") or {}
    if comp_frameworks:
        context["compliance"] = {
            "total_gaps": comp_summary.get("total_gaps"),
            "framework_coverages": [
                {
                    "framework": f.get("framework"),
                    "version": f.get("framework_version"),
                    "modeled_coverage": f.get("modeled_coverage_percentage"),
                    "gaps": f.get("gaps")
                } for f in comp_frameworks
            ]
        }

    # Dynamic Context Expansion: Include specific asset or recommendation if mentioned in question
    all_assets = analysis_data.get("assets") or (intel_raw.get("assets") or [])
    for a in all_assets:
        aid = (a.get("asset_id") or "").lower()
        aname = (a.get("asset_name") or a.get("asset", {}).get("asset_name") or "").lower()
        if aid and (aid in question_lower or (len(aname) > 3 and aname in question_lower)):
            if "specific_asset_detail" not in context:
                context["specific_asset_detail"] = []
            context["specific_asset_detail"].append(a)

    return context
