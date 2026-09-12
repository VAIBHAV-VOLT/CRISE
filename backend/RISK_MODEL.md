# CRISE Modeled Cyber Risk Score — Model Specification

## 1. Overview and Purpose

The CRISE Cyber Risk Engine calculates a transparent, deterministic **Modeled Risk Score** for assets and the enterprise.

> [!IMPORTANT]
> **Model Disclaimer**
> This prototype uses a transparent modeled risk score for comparative prioritization and exploratory planning. It is **not** a certified cybersecurity rating, statistical probability of attack, or guarantee of financial loss. It is designed to be deterministic, explainable, and responsive to user-defined asset, vulnerability, and control parameters.

---

## 2. Core Conceptual Factors

For each asset, the risk engine evaluates six conceptual dimensions:
1. **Asset Criticality**: Operational importance to the business (1 to 5).
2. **Vulnerability Severity**: Weakness severity (0.0 to 10.0, CVSS-style).
3. **Vulnerability Exploitability**: Ease of exploitation (0.0 to 1.0).
4. **Internet Exposure**: External attack surface accessibility (boolean).
5. **Data Sensitivity**: Confidentiality classification of data on the asset (1 to 5).
6. **Existing Security Controls**: Deployed safeguards (effectiveness 0.0 to 1.0, status).

---

## 3. Mathematical Formulation

### 3.1 Individual Vulnerability Exposure
For each vulnerability $v$ assigned to an asset:
$$\text{severity\_factor}_v = \frac{\text{severity}_v}{10.0}$$
$$\text{vulnerability\_exposure}_v = \text{severity\_factor}_v \times \text{exploitability}_v$$

This yields a normalized exposure factor between $0.0$ and $1.0$. It is **not** a real-world probability, but a relative exposure metric.

### 3.2 Combined Vulnerability Exposure
Assets often contain multiple vulnerabilities. To prevent exposure from exceeding $1.0$ while accounting for cumulative risk, a diminishing-return aggregate is used:
$$\text{combined\_vulnerability\_exposure} = 1.0 - \prod_{v \in V} (1.0 - \text{vulnerability\_exposure}_v)$$

If an asset has no vulnerabilities ($V = \emptyset$):
$$\text{combined\_vulnerability\_exposure} = 0.0$$

### 3.3 Security Control Effectiveness & Diminishing Returns
Controls have an `effectiveness` rating ($0.0$ to $1.0$) and an `implementation_status`.
- Only controls where `implementation_status == "Active"` (case-insensitive) mitigate current risk.
- Controls with `implementation_status == "Planned"` do **not** reduce current risk (they are preserved for simulation and investment optimization).

When combining multiple active controls, defense-in-depth follows a diminishing-return assumption:
$$\text{combined\_control\_effectiveness} = 1.0 - \prod_{c \in C_{\text{active}}} (1.0 - \text{effectiveness}_c)$$

*Modeling Assumption*: Each additional control mitigates a fraction of the remaining unmitigated exposure rather than adding linearly.

If no active controls exist:
$$\text{combined\_control\_effectiveness} = 0.0$$

The **remaining exposure** factor is:
$$\text{remaining\_exposure} = 1.0 - \text{combined\_control\_effectiveness}$$

### 3.4 Asset Importance Factors
Normalized to $[0.0, 1.0]$:
$$\text{criticality\_factor} = \frac{\text{criticality}}{5.0}$$
$$\text{sensitivity\_factor} = \frac{\text{data\_sensitivity}}{5.0}$$
$$\text{internet\_factor} = \begin{cases} 1.0 & \text{if internet\_exposed is True} \\ 0.0 & \text{if internet\_exposed is False} \end{cases}$$

### 3.5 Base Exposure
Combining intrinsic risk drivers with transparent weights:
$$\text{base\_exposure} = 0.50 \times \text{combined\_vulnerability\_exposure} + 0.20 \times \text{criticality\_factor} + 0.15 \times \text{sensitivity\_factor} + 0.15 \times \text{internet\_factor}$$

### 3.6 Modeled Risk Score
Active controls act as a mitigating barrier applied to the base exposure:
$$\text{risk\_factor} = \text{base\_exposure} \times \text{remaining\_exposure}$$
$$\text{risk\_score} = \text{round}(\text{clamp}(\text{risk\_factor} \times 100.0, 0.0, 100.0), 2)$$

---

## 4. Risk Categorization Thresholds

Asset and enterprise scores are mapped to discrete, non-overlapping risk levels:

| Score Range | Risk Level | Description |
|---|---|---|
| $0.00 \le \text{Score} \le 25.00$ | **LOW** | Minimal modeled exposure; standard monitoring |
| $25.00 < \text{Score} \le 50.00$ | **MEDIUM** | Moderate exposure; prioritize standard remediation |
| $50.00 < \text{Score} \le 75.00$ | **HIGH** | Significant exposure; near-term remediation required |
| $75.00 < \text{Score} \le 100.00$ | **CRITICAL** | Severe exposure; immediate intervention recommended |

---

## 5. Enterprise Risk Aggregation

The enterprise score does not merely average asset scores, because protecting a mission-critical financial ledger is more impactful than protecting a low-value test server.

$$\text{weighted\_risk} = \sum_{a \in A} (\text{risk\_score}_a \times \text{business\_value}_a)$$
$$\text{total\_business\_value} = \sum_{a \in A} \text{business\_value}_a$$

$$\text{overall\_risk\_score} = \begin{cases} 
\text{round}\left(\frac{\text{weighted\_risk}}{\text{total\_business\_value}}, 2\right) & \text{if } \text{total\_business\_value} > 0 \\
\text{round}\left(\frac{1}{|A|} \sum_{a \in A} \text{risk\_score}_a, 2\right) & \text{if } \text{total\_business\_value} = 0 \text{ (fallback)}
\end{cases}$$

Clamped to $[0.0, 100.0]$ and assigned an enterprise risk level via the standard thresholds.

---

## 6. Explainability Architecture

Each asset result includes a deterministic, rule-based list of explanations describing:
1. Criticality tier (low, medium, high).
2. Vulnerability count and highest severity found.
3. Internet exposure state.
4. Active control mitigation percentage and residual exposure.
