# CRISE Phase 15 — AI Security Analyst Model & Reference

## 1. Purpose & Core Principles

The **AI Security Analyst** provides an explainable, natural-language analysis and interpretation layer over the structured CRISE findings produced by Phases 4–14.

> [!IMPORTANT]
> **Authoritative Engine & Legal Non-Claim Rules**:
> - **Explanation Layer Only**: The AI does NOT calculate official CRISE risk scores, modify risk formulas, or replace deterministic engine outputs. Deterministic engines (Phases 4–14) remain the sole source of truth.
> - **Zero Hallucination / No Invented Facts**: If context lacks information (e.g. unknown malware family or probability of attack), the AI explicitly reports insufficient evidence rather than fabricating answers.
> - **Modeled Disclaimers Preserved**:
>   - Monte Carlo values represent *modeled input parameter uncertainty*, not attack probability.
>   - Compliance coverage represents *CRISE modeled coverage*, NOT legal, regulatory, or audit certification.
>   - MITRE mappings represent *threat scenario crosswalks*, not proof of actual compromise.

---

## 2. Architecture & Data Flow

```text
CSV DATA 
   ↓
CRISE DETERMINISTIC ENGINES (Phases 4–14)
   ↓
Structured Analysis JSON Payload
   ↓
FastAPI Backend (POST /api/ai/analyze)
   ↓
AI Service (OpenAI / OpenAI-Compatible Provider)
   ↓
Natural Language Explanation (Structured JSON Answer)
```

---

## 3. Server-Side Security & Environment Credentials

All LLM provider credentials are kept exclusively on the server side:
- **`AI_PROVIDER`**: Provider type (`openai` or OpenAI-compatible endpoint).
- **`AI_API_KEY`**: Server-side API authentication token.
- **`AI_MODEL`**: Model identifier configured via `.env` (e.g. `gpt-4o-mini`).
- **`AI_BASE_URL`**: Optional custom base URL for OpenAI-compatible APIs.
- **`AI_TEMPERATURE`**: Default `0.2` (low variance for analytical consistency).
- **`AI_MAX_TOKENS`**: Default `1200` tokens limit.

> [!CAUTION]
> **API Key Isolation**: `AI_API_KEY` is NEVER exposed to the frontend, browser, HTML, JS, logs, exception traces, `/api/health`, or `/api/ai/status`.

---

## 4. System Prompt Principles & Prompt Injection Defense

1. **System Prompt Priority**: The system prompt (`SYSTEM_PROMPT` in `ai_prompts.py`) enforces strict persona and calculation immutability.
2. **Prompt Injection Isolation**: User questions and uploaded CSV content (asset names, vulnerability descriptions, control names) are isolated as data blocks and cannot alter system instructions.
3. **Fact vs. Interpretation**: Distinguishes verified CRISE engine facts from AI analytical interpretation.

---

## 5. Supported Queries & Response Schema

### Supported Question Types:
- **Risk**: "Why is our enterprise risk rated this way?", "Which asset needs attention first?"
- **Vulnerabilities**: "Which vulnerability should we remediate first?"
- **Threats**: "What is our most significant threat scenario?"
- **Financial**: "What is our historical annualized loss?"
- **Optimizer**: "Why were these controls selected by the optimizer?"
- **Monte Carlo**: "How uncertain is our risk score?"
- **MITRE ATT&CK**: "Which ATT&CK techniques apply to our incidents?"
- **Compliance**: "What are our biggest compliance gaps?"
- **Executive Summaries**: "Give me a 30-second executive summary."

### Response JSON Schema:
```json
{
  "success": true,
  "answer": "Clear, concise, executive-level explanation...",
  "sources": [
    {
      "type": "CRISE",
      "reference": "risk.overall_score"
    }
  ],
  "confidence": "HIGH",
  "disclaimer": "AI-generated analysis based on CRISE results. Verify critical security decisions against authoritative security guidance."
}
```
