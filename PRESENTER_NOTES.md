# PyRIT Demo — Presenter Notes (10 min)

## Pre-Demo Setup (do this BEFORE the session)

1. **Install PyRIT:**
   ```
   pip install pyrit
   ```

2. **Authenticate via Entra ID (RBAC):**
   ```
   az login
   ```
   - Your account needs the **"Cognitive Services OpenAI User"** role on `foundry-llmops-demo`
   - No API keys needed — the notebook uses `get_azure_openai_auth()` for token-based auth

3. **Configure endpoint** — the `.env` only needs:
   - `OPENAI_CHAT_ENDPOINT` — `https://foundry-llmops-demo.services.ai.azure.com/models`
   - `OPENAI_CHAT_MODEL` — `gpt-4o`

3. **Test connectivity** — run Demo 1 cell once to confirm the target responds.

4. **Pre-run all cells** if you want guaranteed outputs during the live demo.

---

## Talk Track (~10 min)

### [1 min] Intro — What is PyRIT?
- Microsoft's open-source AI red-teaming framework
- Built by the Microsoft AI Red Team for proactive risk identification
- Component-based: Targets, Attacks, Converters, Scorers, Memory
- Goal: test if your LLM's safety guardrails hold up

### [2 min] Demo 1 — Simple Single-Turn Attack
- Show that a plain adversarial prompt gets **refused** ✅ (guardrails work)
- Highlight: `OpenAIChatTarget()` wraps any OpenAI-compatible endpoint
- Highlight: `PromptSendingAttack` = simplest building block
- **Talking point:** "This is the baseline — the model does the right thing"

### [2 min] Demo 2 — Base64 Converter
- Show Original vs Converted prompt (Base64-encoded text)
- The model may or may not decode it — shows how converters probe weaknesses
- **Talking point:** "Attackers encode prompts to evade keyword-based filters.
  PyRIT lets you test this systematically."

### [2 min] Demo 3 — Automatic Scoring
- Show the ✅/❌ verdict and the scorer's rationale
- A **second LLM** judges whether the first LLM leaked harmful info
- **Talking point:** "At scale, you can't read every response manually.
  Scorers automate the judgment."

### [2 min] Demo 4 — Jailbreak Template (DAN)
- Show the DAN system prompt being prepended
- Send 2 adversarial prompts through it
- The model may partially comply — that's a finding!
- **Talking point:** "PyRIT ships with 100+ jailbreak templates.
  You can test your model against known attack patterns."

### [1 min] Demo 5 — Full Pipeline (CharSwap + Refusal Scorer)
- Combines converter + scorer in one pipeline
- Show the char-swapped prompt and automated verdict
- **Talking point:** "This is what production red-teaming looks like —
  mutate, send, score, repeat — fully automated."

### [1 min] Wrap-Up
- Recap: 5 demos, progressively more powerful
- PyRIT scales to millions of prompts
- Open-source, works with Azure OpenAI / OpenAI / any HTTP target
- Links: github.com/Azure/PyRIT + azure.github.io/PyRIT

---

## Q&A Cheat Sheet

**Q: Does it work with non-OpenAI models?**
A: Yes — any HTTP endpoint. There's also `HuggingFaceChatTarget`, `OllamaChatTarget`, etc.

**Q: Can it do multi-turn attacks?**
A: Yes — use `RedTeamingAttack` where an adversarial LLM iteratively refines prompts
   over multiple turns to find jailbreaks.

**Q: Where are results stored?**
A: In-memory for demos, or Azure SQL / DuckDB for production. All prompts,
   responses, and scores are tracked.

**Q: What real-world datasets are available?**
A: PyRIT ships with 46+ seed datasets covering illegal content, bias, hate speech,
   psychosocial harms, copyright violations, etc.

**Q: Is this only for text?**
A: No — PyRIT supports images, audio, and video targets too.
