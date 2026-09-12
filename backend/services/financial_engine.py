"""
Financial Risk Engine Service for Cyber Risk Analyzer (Phase 5).
Translates cybersecurity exposure and empirical incident experience into
transparent, deterministic, and explainable financial risk estimates.

Core Metrics:
1. Historical Annualized Loss: sum(frequency_per_year * average_loss) across incidents.
2. Risk-Based Business Exposure: business_value * (risk_score / 100.0).
3. Modeled Expected Annual Loss (EAL): anchored to historical annualized incident loss.
4. Weighted Annual Downtime: sum(frequency_per_year * downtime_hours).

DISCLAIMER:
Financial outputs are modeled estimates derived from user-supplied business,
incident, and cybersecurity data. They are NOT guaranteed losses, financial forecasts,
actuarial estimates, or predictions of future incidents.
"""

from typing import Any, Dict, List


def calculate_asset_financial_risk(
    asset_profile: Dict[str, Any],
    risk_result: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Calculate modeled financial risk metrics for a single asset.
    Reuses Phase 3 asset profiles and Phase 4 risk results without recalculating risk scores.
    """
    asset_info = asset_profile.get("asset", {})
    asset_id = asset_profile.get("asset_id", "")
    asset_name = asset_info.get("asset_name", asset_id)
    business_value = float(asset_info.get("business_value", 0.0))

    # 1. Process Incidents
    raw_incidents = asset_profile.get("incidents", [])
    incident_records: List[Dict[str, Any]] = []
    total_annualized_loss = 0.0
    total_historical_downtime = 0.0
    total_weighted_downtime = 0.0

    for inc in raw_incidents:
        freq = float(inc.get("frequency_per_year", 0.0))
        avg_loss = float(inc.get("average_loss", 0.0))
        downtime = float(inc.get("downtime_hours", 0.0))
        ann_loss = round(freq * avg_loss, 2)

        total_annualized_loss += ann_loss
        total_historical_downtime += downtime
        total_weighted_downtime += (freq * downtime)

        incident_records.append({
            "incident_id": inc.get("incident_id", ""),
            "incident_type": inc.get("incident_type", ""),
            "frequency_per_year": freq,
            "average_loss": avg_loss,
            "downtime_hours": downtime,
            "annualized_loss": ann_loss,
        })

    incident_count = len(incident_records)
    historical_annualized_loss = round(total_annualized_loss, 2)
    total_historical_downtime = round(total_historical_downtime, 2)
    weighted_annual_downtime = round(total_weighted_downtime, 2)

    # 2. Risk-Based Business Exposure
    # Gross exposure indicator: business_value * (risk_score / 100)
    risk_info = risk_result.get("risk", {})
    risk_score = float(risk_info.get("score", 0.0))
    risk_level = str(risk_info.get("level", "LOW"))
    risk_factor = risk_score / 100.0
    risk_based_business_exposure = round(business_value * risk_factor, 2)

    # 3. Modeled Expected Annual Loss (EAL)
    # Uses empirical incident history as the primary baseline
    modeled_eal = historical_annualized_loss

    # 4. Data Quality & Explanation
    if incident_count > 0:
        historical_data_available = True
        financial_data_quality = "historical_data_available"
        explanation = (
            f"{asset_name} has a modeled risk score of {risk_score} and a business value of "
            f"₹{business_value:,.2f}. Its supplied incident history corresponds to an annualized "
            f"historical loss of ₹{historical_annualized_loss:,.2f}."
        )
    else:
        historical_data_available = False
        financial_data_quality = "no_historical_incidents"
        explanation = (
            f"{asset_name} has no historical incidents in the supplied dataset, so historical "
            f"annualized loss cannot be inferred from incident history."
        )

    return {
        "asset_id": asset_id,
        "asset_name": asset_name,
        "risk_score": risk_score,
        "financial_risk_level": risk_level,
        "financial": {
            "business_value": business_value,
            "historical_annualized_loss": historical_annualized_loss,
            "risk_based_business_exposure": risk_based_business_exposure,
            "modeled_eal": modeled_eal,
            "incident_count": incident_count,
            "total_historical_downtime_hours": total_historical_downtime,
            "weighted_annual_downtime_hours": weighted_annual_downtime,
            "historical_data_available": historical_data_available,
            "financial_data_quality": financial_data_quality,
            "explanation": explanation,
        },
        "incidents": incident_records,
    }


def calculate_financial_risk(
    processed_data: Dict[str, Any],
    risk_results: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Calculate enterprise-level modeled financial risk metrics across all assets.

    Computes:
      - Per-asset financial results
      - Enterprise totals: total business value, historical annualized loss,
        risk-based business exposure, incident count, downtime metrics
      - Top historical-loss assets (top 10 sorted descending)
      - Top risk-exposure assets (top 10 sorted descending)
      - Breakdown by cybersecurity risk level (critical, high, medium, low)
    """
    raw_assets = processed_data.get("assets", [])
    scored_assets = risk_results.get("assets", [])

    # Index scored assets by asset_id for fast lookup
    scored_map = {a.get("asset_id"): a for a in scored_assets}

    asset_financial_results: List[Dict[str, Any]] = []
    for raw_asset in raw_assets:
        aid = raw_asset.get("asset_id")
        matching_risk = scored_map.get(aid, {})
        fin_res = calculate_asset_financial_risk(raw_asset, matching_risk)
        asset_financial_results.append(fin_res)

    # Enterprise Summary Totals
    total_business_value = round(sum(a["financial"]["business_value"] for a in asset_financial_results), 2)
    total_historical_loss = round(sum(a["financial"]["historical_annualized_loss"] for a in asset_financial_results), 2)
    total_risk_exposure = round(sum(a["financial"]["risk_based_business_exposure"] for a in asset_financial_results), 2)
    total_incidents = sum(a["financial"]["incident_count"] for a in asset_financial_results)
    total_historical_downtime = round(sum(a["financial"]["total_historical_downtime_hours"] for a in asset_financial_results), 2)
    total_weighted_downtime = round(sum(a["financial"]["weighted_annual_downtime_hours"] for a in asset_financial_results), 2)

    ent_quality = "historical incident data available" if total_incidents > 0 else "no historical incident data available"

    # Top Assets by Historical Annualized Loss
    sorted_by_hist = sorted(
        asset_financial_results,
        key=lambda a: a["financial"]["historical_annualized_loss"],
        reverse=True
    )
    top_historical_loss_assets = [
        {
            "asset_id": a["asset_id"],
            "asset_name": a["asset_name"],
            "historical_annualized_loss": a["financial"]["historical_annualized_loss"],
            "financial_risk_level": a["financial_risk_level"],
        }
        for a in sorted_by_hist[:10]
    ]

    # Top Assets by Risk-Based Business Exposure
    sorted_by_exp = sorted(
        asset_financial_results,
        key=lambda a: a["financial"]["risk_based_business_exposure"],
        reverse=True
    )
    top_risk_exposure_assets = [
        {
            "asset_id": a["asset_id"],
            "asset_name": a["asset_name"],
            "business_value": a["financial"]["business_value"],
            "risk_score": a["risk_score"],
            "risk_based_business_exposure": a["financial"]["risk_based_business_exposure"],
            "financial_risk_level": a["financial_risk_level"],
        }
        for a in sorted_by_exp[:10]
    ]

    # Aggregation by Cyber Risk Level
    by_risk_level: Dict[str, Dict[str, Any]] = {
        "critical": {"asset_count": 0, "business_value": 0.0, "historical_annualized_loss": 0.0, "risk_based_business_exposure": 0.0},
        "high": {"asset_count": 0, "business_value": 0.0, "historical_annualized_loss": 0.0, "risk_based_business_exposure": 0.0},
        "medium": {"asset_count": 0, "business_value": 0.0, "historical_annualized_loss": 0.0, "risk_based_business_exposure": 0.0},
        "low": {"asset_count": 0, "business_value": 0.0, "historical_annualized_loss": 0.0, "risk_based_business_exposure": 0.0},
    }

    for a in asset_financial_results:
        lvl = a["financial_risk_level"].lower()
        if lvl in by_risk_level:
            by_risk_level[lvl]["asset_count"] += 1
            by_risk_level[lvl]["business_value"] = round(by_risk_level[lvl]["business_value"] + a["financial"]["business_value"], 2)
            by_risk_level[lvl]["historical_annualized_loss"] = round(by_risk_level[lvl]["historical_annualized_loss"] + a["financial"]["historical_annualized_loss"], 2)
            by_risk_level[lvl]["risk_based_business_exposure"] = round(by_risk_level[lvl]["risk_based_business_exposure"] + a["financial"]["risk_based_business_exposure"], 2)

    return {
        "success": True,
        "financial_summary": {
            "total_business_value": total_business_value,
            "historical_annualized_loss": total_historical_loss,
            "risk_based_business_exposure": total_risk_exposure,
            "incident_count": total_incidents,
            "historical_downtime_hours": total_historical_downtime,
            "weighted_annual_downtime_hours": total_weighted_downtime,
            "financial_data_quality": ent_quality,
        },
        "top_historical_loss_assets": top_historical_loss_assets,
        "top_risk_exposure_assets": top_risk_exposure_assets,
        "by_risk_level": by_risk_level,
        "assets": asset_financial_results,
    }
