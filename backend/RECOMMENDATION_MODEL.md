# Cybersecurity Recommendation Model (Phase 11)

## Overview
The Phase 11 Recommendation Engine generates **deterministic, explainable, prioritized cybersecurity recommendations** by consuming the outputs of preceding analysis phases:
- **Phase 4 Risk Engine** (Modeled Asset & Enterprise Risk Scores, Risk Levels)
- **Phase 5 Financial Engine** (Historical Annualized Losses, Asset Business Values)
- **Phase 6 Threat Engine** (Threat Scenarios, Event Frequencies)
- **Phase 8 Intelligence Engine** (Asset & Vulnerability Intelligence Profiles)
- **Phase 10 Investment Optimizer** (Recommended Budget Portfolio Selections)

---

## Core Principles
1. **Zero Invented Data**: All metrics, severities, costs, and exposures are derived strictly from user-supplied CSV datasets or Phase 4–10 backend computations.
2. **Deterministic Prioritization & Ordering**: Recommendations are ordered deterministically using a explicit multi-key tie-breaker.
3. **Stateless Execution**: Operates in-memory without persistence, database storage, or external API calls.
4. **No Probabilistic Claims**: All impact statements describe modeled risk reductions and exposure mitigations without claiming real-world likelihoods.

---

## Recommendation Categories & Evidence Sources

| Category | Trigger / Evidence Source | Default Action | Primary Impact |
| :--- | :--- | :--- | :--- |
| **`ASSET_PROTECTION`** | Assets with Risk Score $\ge 60.0$ or Risk Level `HIGH`/`CRITICAL` | Review and apply comprehensive security controls | Reduces overall asset exposure factor |
| **`VULNERABILITY_REMEDIATION`** | Vulnerabilities with Severity $\ge 6.0$, Exploitability $\ge 0.6$, or Exposure $\ge 0.36$ | Patch or remediate vulnerability | Eliminates vulnerability exposure factor $\frac{\text{Severity}}{10} \times \text{Exploitability}$ |
| **`CONTROL_IMPLEMENTATION`** | Inactive/Planned controls present on asset | Deploy and activate security control | Achieves control effectiveness $\% \text{ reduction}$ |
| **`EXPOSURE_REDUCTION`** | Asset flagged as `internet_exposed = true` | Isolate or restrict public internet accessibility | Removes internet exposure multiplier |
| **`INCIDENT_MITIGATION`** | Asset with historical incidents or $>\text{₹}0$ annualized loss | Apply targeted incident controls & protocols | Reduces recurrence probability of historical loss |

---

## Vulnerability Exposure Formula
The exposure contribution of each vulnerability is defined as:
$$\text{vulnerability\_exposure} = \left(\frac{\text{Severity}}{10.0}\right) \times \text{Exploitability}$$

Where:
- $\text{Severity} \in [0.0, 10.0]$
- $\text{Exploitability} \in [0.0, 1.0]$

---

## Priority Assignment Rules

1. **CRITICAL**:
   - Asset Risk Level is `CRITICAL`, or Risk Score $\ge 80.0$.
   - Vulnerability with Severity $\ge 9.0$ AND Exploitability $\ge 0.8$ (Elevated Priority Rule).
   - Inactive control selected by Phase 10 Investment Optimizer for a `HIGH` or `CRITICAL` asset.
   - Historical annualized loss $\ge \text{₹}500,000$.

2. **HIGH**:
   - Asset Risk Level is `HIGH`, or Risk Score $\ge 60.0$.
   - Vulnerability Severity $\ge 7.0$ or Vulnerability Exposure $\ge 0.5$.
   - Control effectiveness $\ge 0.70$.
   - Internet-exposed asset.
   - Historical annualized loss $\ge \text{₹}100,000$.

3. **MEDIUM**:
   - Vulnerability Severity $\ge 4.0$.
   - Control effectiveness $\ge 0.40$.
   - Historical incident loss $< \text{₹}100,000$.

4. **LOW**:
   - Standard operational tasks, low-severity vulnerabilities, or low-effectiveness controls.

---

## Deterministic Ordering

All recommendations are sorted using the following strict tuple key:
$$\text{SortKey} = \big(-\text{PriorityWeight},\; -\text{RiskScore},\; -\text{Severity},\; -\text{Exploitability},\; \text{Cost},\; \text{Title}\big)$$

1. **Priority Weight (DESC)**: `CRITICAL` (4) > `HIGH` (3) > `MEDIUM` (2) > `LOW` (1)
2. **Asset Modeled Risk Score (DESC)**
3. **Vulnerability Severity (DESC)** (0.0 if N/A)
4. **Vulnerability Exploitability (DESC)** (0.0 if N/A)
5. **Estimated Annual Cost (ASC)**
6. **Recommendation Title (ASC)**

Recommendation IDs are assigned sequentially following sorting as `REC-001`, `REC-002`, ..., `REC-N`.

---

## Quick Wins

**Quick-Win Recommendations** are identified as actionable items that provide immediate high risk reduction at minimal investment:
- `CONTROL_IMPLEMENTATION` with $\text{Estimated Annual Cost} \le \text{₹}50,000$ AND (Effectiveness $\ge 50\%$ OR Priority $\in \{\text{CRITICAL}, \text{HIGH}\}$).
- `VULNERABILITY_REMEDIATION` with Priority $\in \{\text{CRITICAL}, \text{HIGH}\}$ (0 annual cost).

---

## API Output Schema

```json
{
  "status": "ok",
  "summary": {
    "total_recommendations": 5,
    "critical": 1,
    "high": 2,
    "medium": 2,
    "low": 0
  },
  "recommendations": [
    {
      "recommendation_id": "REC-001",
      "priority": "CRITICAL",
      "category": "VULNERABILITY_REMEDIATION",
      "title": "Remediate 9.8-Severity Vulnerability V001 on ERP Server",
      "asset_id": "A001",
      "asset_name": "ERP Server",
      "reason": "Vulnerability V001 presents exposure factor of 0.78 (Severity 9.8, Exploitability 0.8).",
      "evidence": {
        "risk_score": 85.5,
        "risk_level": "CRITICAL",
        "vulnerability_id": "V001",
        "severity": 9.8,
        "exploitability": 0.8,
        "vulnerability_exposure": 0.784
      },
      "recommended_action": "Patch or remediate vulnerability V001 (Outdated Software) on asset ERP Server.",
      "expected_impact": {
        "type": "modeled_risk_reduction",
        "description": "Eliminates vulnerability exposure factor of 0.78 associated with V001."
      },
      "related_control_ids": ["C001"],
      "estimated_annual_cost": 0.0
    }
  ],
  "quick_wins": [...]
}
```
