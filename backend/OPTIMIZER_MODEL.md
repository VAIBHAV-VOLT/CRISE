# CRISE Investment Optimizer Model Specification (Phase 10)

## Overview
The **CRISE Investment Optimizer** provides deterministic, budget-constrained decision support to answer:

> *"Given a cybersecurity budget of ₹X, which available security controls should we invest in to achieve the greatest reduction in enterprise modeled risk?"*

---

## 1. Modeling Assumptions & Boundaries

1. **Discrete Investment Actions**:
   Each eligible control (defined as a control whose current `implementation_status` is not active, e.g., `Planned`, `Inactive`, or `Not Implemented`) is treated as a discrete investment action:
   $$\text{Investment Action} \longrightarrow \text{Pay } \text{annual\_cost} \longrightarrow \text{Activate control with supplied } \text{effectiveness}$$
2. **Fixed Cost-Effectiveness Data**:
   The input dataset does NOT specify a continuous cost-effectiveness curve ($\text{₹}X \rightarrow +Y\%$). Therefore, the optimizer does not invent arbitrary scaling formulas or assume that spending more money proportionally increases control effectiveness beyond the supplied data.
3. **No Double Counting**:
   When multiple controls affect the same asset, their effectiveness values are combined using Phase 4's diminishing-returns formula:
   $$\text{combined\_control\_effectiveness} = 1 - \prod_{i} (1 - \text{effectiveness}_i)$$
   Controls are NOT combined by simply adding percentage points.

---

## 2. Optimization Objective & Constraints

$$\begin{aligned}
\min_{\mathbf{x}} \quad & \text{EnterpriseModeledRisk}(\mathbf{x}) \\
\text{subject to} \quad & \sum_{i \in \text{Selected}} \text{annual\_cost}_i \le \text{Budget} \\
& x_i \in \{0, 1\} \quad \forall i \in \text{EligibleControls}
\end{aligned}$$

Where Enterprise Modeled Risk is the business-value weighted risk score from Phase 4:
$$\text{Enterprise Risk} = \frac{\sum (\text{asset\_risk\_score} \times \text{business\_value})}{\sum \text{business\_value}}$$
*(With arithmetic mean fallback if total business value is zero).*

---

## 3. Optimization Algorithms

### A. Exact Subset Mode ($N \le 20$ eligible candidate controls)
- **Algorithm**: Evaluates all $2^N$ possible subsets of eligible controls.
- **Feasibility Filter**: Keeps only subsets where $\sum \text{annual\_cost}_i \le \text{Budget}$.
- **Evaluation**: Calculates the exact Phase 4 enterprise risk score for each feasible subset using a temporary deep copy of the dataset.
- **Selection**: Selects the portfolio with the **minimum enterprise risk score**.
- **Tie-Breaking**: If multiple portfolios achieve the same minimum risk score, selects the portfolio with the lowest total cost, followed by lexicographical control ID ordering.
- **Status Flag**: `algorithm: {"method": "exact_subset", "is_optimal": true}`.

### B. Greedy Mode ($N > 20$ eligible candidate controls)
- **Algorithm**: Iterative greedy heuristic.
- **Selection Criterion**: At each step, evaluates all remaining affordable controls and selects the control yielding the highest marginal enterprise risk reduction and risk-reduction-per-rupee ratio.
- **Tie-Breaking**: Higher marginal risk reduction $\rightarrow$ higher reduction per rupee $\rightarrow$ lower cost $\rightarrow$ lower control ID.
- **Status Flag**: `algorithm: {"method": "greedy", "is_optimal": false}`.

---

## 4. Output Metrics & Transparency

- **Budget Summary**: `available`, `used`, `remaining`.
- **Impact Metrics**: `baseline_risk_score`, `optimized_risk_score`, `risk_reduction`, `percentage_reduction`.
- **Selected Controls**: List of selected controls with `marginal_risk_reduction` and `risk_reduction_per_rupee`.
- **Affected Assets**: List of assets whose modeled risk score changed.
- **Risk-Level Transitions**: Detailed list of asset risk level movements (e.g. `HIGH` $\rightarrow$ `MEDIUM`).
- **Explanation**: Deterministic, non-AI rule-based summary explaining the selected investment portfolio.
