<h1 align="center">🎯 PyRIT Red-Team Demo</h1>

<p align="center">
  <strong>Red-team your Azure OpenAI models in 10 minutes</strong><br>
  Interactive notebook · One-command HTML report · Live attack dashboard
</p>

<p align="center">
  <a href="https://github.com/Azure/PyRIT"><img src="https://img.shields.io/badge/PyRIT-v0.11-blue?logo=python" alt="PyRIT"></a>
  <a href="https://azure.microsoft.com/products/ai-services/openai-service"><img src="https://img.shields.io/badge/Azure_OpenAI-GPT--4o%20|%20GPT--5--mini%20|%20o4--mini-0078D4?logo=microsoftazure" alt="Azure OpenAI"></a>
  <a href="https://learn.microsoft.com/azure/ai-studio/"><img src="https://img.shields.io/badge/Azure_AI_Foundry-Phi--4_Multimodal-purple?logo=microsoftazure" alt="AI Foundry"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-green" alt="MIT License"></a>
</p>

---

## 🚀 What Is This?

A hands-on demo of [**PyRIT**](https://github.com/Azure/PyRIT) (Python Risk Identification Tool) — Microsoft's open-source framework for **finding safety vulnerabilities in LLMs** before bad actors do.

This repo gives you **three ways** to red-team your AI:

| Tool | What it does | How to run |
|------|-------------|------------|
| 📓 **Interactive Notebook** | Walk through 4 attack demos step-by-step | `PyRIT_Demo.ipynb` |
| 📊 **Static HTML Report** | Run 7 automated tests → beautiful HTML report | `python run_red_team.py` |
| ⚡ **Live Dashboard** | Real-time web app to fire attacks interactively | `python live_dashboard.py` |

---

## 🎬 Demo Lineup

### 📓 Notebook Demos

| # | Demo | Technique | What you'll see |
|---|------|-----------|----------------|
| 1 | 🎭 **Nice Try!** | Direct prompt | Model refuses a harmful request |
| 2 | 🕵️ **Speak in Code** | Base64 encoding | Prompt disguised as encoded text |
| 3 | ⚖️ **The AI Judge** | Auto-scoring | Second LLM grades the response |
| 4 | 🔓 **Jailbreak Showdown** | DAN template | Famous jailbreak vs. guardrails |

### 📊 Static Report (7 Tests)

| Test | Technique |
|------|-----------|
| T1 | Direct harmful prompt |
| T2 | Base64-encoded prompt |
| T3 | Character swap obfuscation |
| T4 | AI-scored evaluation |
| T5-T6 | DAN jailbreak (2 prompts) |
| T7 | Refusal detection |

### ⚡ Live Dashboard Features

- **6 attack techniques**: Direct, Base64, CharSwap, AI-Scored, DAN Jailbreak, Image+Text
- **4 models**: GPT-4o, GPT-5-mini, o4-mini, Phi-4 Multimodal
- **Image upload**: Test multimodal attacks with text + image
- **Real-time results**: Auto-updating cards with BLOCKED/BYPASSED status
- **Stats bar**: Live counters for total, blocked, bypassed, and running tests
- **Keyboard shortcut**: Ctrl+Enter to fire

---

## 📋 Prerequisites

- **Python 3.10 – 3.13** (PyRIT does not support 3.14+)
- **Azure subscription** with:
  - Azure OpenAI resource with model deployments
  - (Optional) Azure AI Foundry project for Phi-4 models
- **Azure CLI** logged in: `az login`
- **RBAC role**: `Cognitive Services OpenAI User` on your Azure OpenAI resource

### Assign the RBAC Role

```bash
# Get your user object ID
USER_ID=$(az ad signed-in-user show --query id -o tsv)

# Assign the role (replace with your resource ID)
az role assignment create \
  --assignee $USER_ID \
  --role "Cognitive Services OpenAI User" \
  --scope /subscriptions/<SUB_ID>/resourceGroups/<RG>/providers/Microsoft.CognitiveServices/accounts/<AOAI_NAME>
```

---

## ⚙️ Setup

### 1. Clone the repo

```bash
git clone https://github.com/ritwickmicrosoft/pyrit-demo.git
cd pyrit-demo
```

### 2. Create a virtual environment

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install pyrit fastapi uvicorn python-multipart
```

### 4. Configure endpoints

Edit the top of `live_dashboard.py` and `run_red_team.py` with your Azure OpenAI endpoint:

```python
AOAI_ENDPOINT = "https://<your-resource>.openai.azure.com/openai/v1"
```

For the notebook, update `ENDPOINT` in the setup cell.

---

## 🏃 Quick Start

### Option 1: Interactive Notebook

```bash
jupyter notebook PyRIT_Demo.ipynb
```

Run cells sequentially — each demo takes ~30 seconds.

### Option 2: One-Command HTML Report

```bash
python run_red_team.py
```

Generates `red_team_report.html` and auto-opens it in your browser. 7 tests, ~2 minutes.

### Option 3: Live Dashboard

```bash
python live_dashboard.py
```

Open **http://localhost:8765** — type prompts, pick models, fire attacks, watch results live.

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Your Prompts                         │
│         (text, Base64, CharSwap, jailbreak)             │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│                   PyRIT Framework                        │
│  ┌──────────┐  ┌────────────┐  ┌──────────────────────┐ │
│  │ Converter │→ │   Attack    │→ │      Scorer          │ │
│  │ (Base64,  │  │ (Sending,  │  │ (TrueFalse,          │ │
│  │  CharSwap │  │  Jailbreak)│  │  SelfAsk)            │ │
│  │  ROT13)   │  │            │  │                      │ │
│  └──────────┘  └────────────┘  └──────────────────────┘ │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────┐
│              Azure AI Endpoints                          │
│  ┌─────────┐ ┌──────────┐ ┌────────┐ ┌──────────────┐  │
│  │ GPT-4o  │ │GPT-5-mini│ │o4-mini │ │Phi-4 Multimod│  │
│  └─────────┘ └──────────┘ └────────┘ └──────────────┘  │
│       Azure OpenAI              Azure AI Foundry        │
└─────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
pyrit-demo/
├── PyRIT_Demo.ipynb      # 📓 Interactive notebook (4 demos)
├── run_red_team.py       # 📊 Static HTML report generator (7 tests)
├── live_dashboard.py     # ⚡ Live web dashboard (FastAPI + uvicorn)
├── PRESENTER_NOTES.md    # 🎤 10-minute talk track
├── uploads/              # 📎 Temp storage for image uploads
└── README.md             # 📖 You are here
```

---

## 🤝 Key Concepts

| Concept | Description |
|---------|-------------|
| **Target** | The LLM you're testing (GPT-4o, Phi-4, etc.) |
| **Attack** | Sends prompts to the target (`PromptSendingAttack`) |
| **Converter** | Transforms prompts before sending (Base64, CharSwap, ROT13) |
| **Scorer** | Evaluates if the attack succeeded (`SelfAskTrueFalseScorer`) |
| **Jailbreak** | System prompt that tries to bypass safety (`TextJailBreak`) |

Converters and scorers are **composable** — mix and match them like LEGO blocks:

```python
attack = PromptSendingAttack(
    objective_target=target,
    attack_converter_config=AttackConverterConfig(
        request_converters=PromptConverterConfiguration.from_converters(
            converters=[Base64Converter(), CharSwapConverter()]
        )
    ),
    attack_scoring_config=AttackScoringConfig(
        objective_scorer=SelfAskTrueFalseScorer(...)
    ),
)
```

---

## 🔐 Authentication

This demo uses **Microsoft Entra ID (RBAC)** — no API keys needed:

```python
from azure.identity import DefaultAzureCredential

credential = DefaultAzureCredential()
token = credential.get_token("https://cognitiveservices.azure.com/.default").token
```

Just run `az login` before starting, and make sure your account has the **Cognitive Services OpenAI User** role.

---

## 📚 Resources

- **PyRIT Documentation**: [azure.github.io/PyRIT](https://azure.github.io/PyRIT/)
- **PyRIT GitHub**: [github.com/Azure/PyRIT](https://github.com/Azure/PyRIT)
- **Azure OpenAI**: [learn.microsoft.com/azure/ai-services/openai](https://learn.microsoft.com/azure/ai-services/openai/)
- **Azure AI Foundry**: [learn.microsoft.com/azure/ai-studio](https://learn.microsoft.com/azure/ai-studio/)
- **Responsible AI**: [microsoft.com/ai/responsible-ai](https://www.microsoft.com/ai/responsible-ai)

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  Built with ❤️ by <a href="https://github.com/ritwickmicrosoft">Ritwick Dutta</a> using <a href="https://github.com/Azure/PyRIT">PyRIT</a>
</p>
