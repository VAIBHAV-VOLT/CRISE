# CRISE Threat & Scenario Model — Specification

## 1. Overview and Purpose

The CRISE Threat & Scenario Engine synthesizes empirical incident history with cybersecurity risk context to produce a deterministic, explainable scenario analysis.

> [!IMPORTANT]
> **Model Disclaimer**
> Threat and scenario evaluations are **descriptive and modeling-focused**, not predictive intelligence. Scenarios are derived solely from user-supplied incident records. The model does **not** predict future attack likelihoods, calculate probabilities of compromise, or invent hypothetical threat actors.

---

## 2. Derivation of Scenario Categories

1. **Category Source**: The primary scenario type is the distinct `incident_type` supplied in the incident dataset (e.g., *Ransomware*, *Data Breach*, *DDoS*, *Credential Theft*).
2. **Deterministic Scenario Identifiers**: Scenarios are sorted alphabetically by `scenario_type` and assigned deterministic identifiers: `SCN-001`, `SCN-002`, `SCN-003`, etc.
3. **No Invented Categories**: If an incident type is not in the user's data, it does not appear as a scenario.

---

## 3. Mathematical Formulation

### 3.1 Supplied Annual Frequency
For a scenario category $S$ encompassing incident set $I_S$:
$$\text{total\_supplied\_frequency\_per\_year}_S = \sum_{i \in I_S} \text{frequency\_per\_year}_i$$

*Crucial Modeling Principle*: This metric represents the user-supplied historical occurrence rate. It is **never** presented as an attack probability or percentage likelihood.

### 3.2 Historical Annualized Loss
$$\text{historical\_annualized\_loss}_S = \sum_{i \in I_S} (\text{frequency\_per\_year}_i \times \text{average\_loss}_i)$$

All loss numbers stem strictly from supplied frequencies and average losses. No monetary losses are inferred from cyber risk scores.

### 3.3 Operational Downtime Metrics
- **Total Historical Downtime**:
  $$\text{total\_historical\_downtime}_S = \sum_{i \in I_S} \text{downtime\_hours}_i$$
- **Weighted Annual Downtime**:
  $$\text{weighted\_annual\_downtime}_S = \sum_{i \in I_S} (\text{frequency\_per\_year}_i \times \text{downtime\_hours}_i)$$

### 3.4 Affected Assets & Business Value
- **Unique Affected Assets**: The deduplicated set of assets $A_S$ associated with incidents in $I_S$.
- **Affected Asset Count**: $|A_S|$.
- **Affected Asset Business Value**:
  $$\text{affected\_asset\_business\_value}_S = \sum_{a \in A_S} \text{business\_value}_a$$

*Data Integrity Rule*: If multiple incidents under scenario $S$ affect the same asset $a$, $a$'s `business_value` is counted **only once**. Business value is not multiplied by frequency or treated as loss.

---

## 4. Risk Context & Highest-Risk Asset

Each unique affected asset inherits its cybersecurity score and level from Phase 4:
- **Highest-Risk Asset**: The asset in $A_S$ with the maximum Phase 4 `risk_score`.
  - *Tie-breaking*: Resolved deterministically by selecting the lowest `asset_id` lexicographically (e.g. `A001` before `A002`).
- **Highest Risk Score**: $\max_{a \in A_S} (\text{risk\_score}_a)$.
- **Highest Risk Level**: Assigned based on Phase 4 thresholds:
  - $0.0 \le \text{Score} \le 25.0 \implies \mathbf{LOW}$
  - $25.0 < \text{Score} \le 50.0 \implies \mathbf{MEDIUM}$
  - $50.0 < \text{Score} \le 75.0 \implies \mathbf{HIGH}$
  - $75.0 < \text{Score} \le 100.0 \implies \mathbf{CRITICAL}$
- **Scenario Risk Level**: Matches the `highest_risk_level` among its affected assets.
- **Average Affected Asset Risk Score**: $\frac{1}{|A_S|} \sum_{a \in A_S} \text{risk\_score}_a$.
- **Business-Value Weighted Risk Score**:
  $$\text{weighted\_score}_S = \begin{cases}
  \frac{\sum_{a \in A_S} (\text{risk\_score}_a \times \text{business\_value}_a)}{\text{affected\_asset\_business\_value}_S} & \text{if } \text{affected\_asset\_business\_value}_S > 0 \\
  \text{average\_affected\_asset\_risk\_score}_S & \text{otherwise}
  \end{cases}$$

---

## 5. Worked Example (Ransomware Scenario)

From the demo dataset, incidents matching `"Ransomware"`:
- `I001` on `A001` (BV: ₹50M, Risk Score: 11.66, Level: LOW): freq 0.30, avg loss ₹5M, downtime 24h
  - Annualized loss: $0.30 \times 5\text{M} = \text{₹}1,500,000$
  - Weighted downtime: $0.30 \times 24 = 7.2\text{h}$
- `I008` on `A009` (BV: ₹4M, Risk Score: 30.65, Level: MEDIUM): freq 0.10, avg loss ₹4M, downtime 16h
  - Annualized loss: $0.10 \times 4\text{M} = \text{₹}400,000$
  - Weighted downtime: $0.10 \times 16 = 1.6\text{h}$
- `I018` on `A005` (BV: ₹6M, Risk Score: 25.84, Level: MEDIUM): freq 0.15, avg loss ₹3.5M, downtime 16h
  - Annualized loss: $0.15 \times 3.5\text{M} = \text{₹}525,000$
  - Weighted downtime: $0.15 \times 16 = 2.4\text{h}$
- `I024` on `A014` (BV: ₹12M, Risk Score: 10.36, Level: LOW): freq 0.06, avg loss ₹8.5M, downtime 28h
  - Annualized loss: $0.06 \times 8.5\text{M} = \text{₹}510,000$
  - Weighted downtime: $0.06 \times 28 = 1.68\text{h}$

### Aggregate Results:
- **Total Supplied Frequency**: $0.30 + 0.10 + 0.15 + 0.06 = \mathbf{0.61\text{ events/year}}$
- **Historical Annualized Loss**: $1,500,000 + 400,000 + 525,000 + 510,000 = \mathbf{₹2,935,000.00}$
- **Total Historical Downtime**: $24 + 16 + 16 + 28 = \mathbf{84.0\text{ hours}}$
- **Weighted Annual Downtime**: $7.2 + 1.6 + 2.4 + 1.68 = \mathbf{12.88\text{ hours/year}}$
- **Unique Affected Assets**: 4 (`A001`, `A005`, `A009`, `A014`)
- **Affected Asset Business Value**: $50\text{M} + 6\text{M} + 4\text{M} + 12\text{M} = \mathbf{₹72,000,000.00}$
- **Highest-Risk Asset**: `A009` (VPN Gateway, Risk Score: 30.65, Level: MEDIUM)
- **Scenario Risk Level**: `MEDIUM`

---

## 6. Zero-Incident Handling

If an input dataset contains no incidents:
```json
{
  "status": "no_incident_history",
  "scenario_count": 0,
  "scenarios": [],
  "message": "No incident history is available for threat/scenario analysis."
}
```
The system returns HTTP 200 without error.
