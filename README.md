# Privacy-Preserving LLM Gateway

[![CI](https://github.com/Bolliboinapavansai/shard-llm/actions/workflows/ci.yml/badge.svg)](https://github.com/Bolliboinapavansai/shard-llm/actions/workflows/ci.yml)

A small, fully tested reference implementation of a secure LLM request gateway. It catches and redacts PII before a prompt ever reaches an LLM provider, protects the redaction mapping with a secret-shared encryption key (Shamir's Secret Sharing), and writes structured, PII-free audit logs for observability.

The repo is deliberately kept small — about 350 lines across four modules — so the whole design can be read and understood in one sitting. The point isn't to chase state-of-the-art PII recall or production-grade cryptography; it's to show the pipeline and the secure key-handling pattern end to end, clearly enough that every decision is easy to follow.

## Why I built this

I've spent the last several years building production LLM infrastructure in an enterprise banking environment: an Azure API Management gateway sitting in front of Azure OpenAI deployments, handling rate limits, auth, and routing across model versions, plus an observability pipeline that publishes token usage, latency, and prompt/response logs for compliance auditing.

That work left me with a question I couldn't fully answer using a bank's existing compliance tooling: how do you get the observability and auditability enterprise LLM platforms need, without letting sensitive data ever reach the model provider or sit in a log in plaintext? This repo is my attempt to prototype an answer, bringing together two things:

- **Cloud/platform engineering** — the gateway pattern and structured observability, drawn directly from my production APIM/LLM-observability work.
- **Secure computation** — using Shamir secret sharing to protect the vault key, and reversible tokenization instead of destructive redaction. This is the area I want to go deeper into for PhD research.

## How it works

```
                    ┌─────────────────────────────────────────┐
                    │         PrivacyPreservingGateway         │
                    │                                           │
  raw prompt  ───▶  │  1. PIIVault created (fresh Fernet key)  │
                    │  2. Key split into 5 shares (3-of-5)     │
                    │  3. redact(): regex-detect PII, replace  │
                    │     with opaque tokens [EMAIL_ab12cd]    │
                    │  4. vault mapping encrypted (Fernet)      │
                    │                                           │
                    │  ── redacted prompt only ──▶  LLM ───┐   │
                    │                                       │   │
                    │  5. key reconstructed from 3 shares  │   │
                    │  6. vault decrypted                  ◀───┘
                    │  7. rehydrate(): tokens → original    │
                    │  8. audit log written (no raw PII)   │
                    └─────────────────────────────────────────┘
                              │
                              ▼
                 demo_logs/audit_log.jsonl  (JSON Lines,
                 modeled on Azure APIM's LLM gateway log schema)
```

### Why split the vault key with Shamir's Secret Sharing?

A single stored decryption key is a single point of failure — whoever holds it, or whatever service holds it, can decrypt every PII vault. Splitting the key into `N` shares with a reconstruction threshold of `K` changes that picture:

- No individual share leaks any information about the key. This is information-theoretic security, not just "hard to crack."
- Getting hold of fewer than `K` shares gives an attacker nothing usable.
- In a real deployment, the `K` shares would live with separate services, HSMs, or on-call engineers, which models a genuine multi-party trust boundary instead of "one admin holds the master key."

The mechanism itself lives in `src/secret_sharing.py`, and it's wired into the working pipeline in `src/pii_redactor.py` and `src/gateway.py`. Unit tests check both that reconstruction works with enough shares, and that sub-threshold shares reveal nothing about the secret.

## Things people tend to ask about this project

**If someone gets 2 of the 5 key shares, can they read any part of the vault?**

No — and this is the property that separates Shamir's Secret Sharing from just cutting a password into pieces. Below the threshold (3 of 5 here), the remaining shares are consistent with every possible key value, not a narrowed-down set of likely candidates. It's information-theoretic security: not "computationally expensive to crack," but mathematically impossible to extract any information from, no matter how much computing power you throw at it. Compare that to knowing 2 of 4 digits of a PIN, which does narrow the search space — Shamir shares below threshold narrow nothing at all.

**Why not just use a single password or key?**

Because a single key is a single point of compromise. Whoever holds it — a person, a config file, a server — can decrypt everything, and compromising that one thing compromises the whole vault. Splitting the key means an attacker has to compromise `K` independent locations at once, which in a real deployment means `K` separate services or custodians agreeing, not one admin holding a master key. It's the difference between one lock/one key and a K-of-N arrangement, closer to how multi-signature vault access works in banking.

**What's the actual weak point in the PII detection, and how would you fix it?**

It's regex-based, so it only catches PII that matches a fixed pattern — an `@` and a domain for emails, `XXX-XX-XXXX` for SSNs, and so on. It has no understanding of context or meaning, so it misses anything that doesn't fit a hard-coded shape: names, home addresses, informally written phone numbers, company-specific identifiers. The fix is a hybrid approach — keep the regex for cheap, reliable matching on well-defined formats like SSNs, emails, and credit cards, and layer a Named Entity Recognition model on top to catch the context-dependent PII that regex structurally can't. That's roughly how production PII detection systems are actually built.

## Project structure

```
llm-privacy-gateway/
├── src/
│   ├── secret_sharing.py   # Shamir's Secret Sharing over GF(p)
│   ├── pii_redactor.py     # PII detection, tokenization, encrypted vault
│   ├── audit_logger.py     # Structured, PII-free JSONL audit logging
│   └── gateway.py          # Orchestrates the full request pipeline
├── tests/
│   ├── test_secret_sharing.py
│   ├── test_pii_redactor.py
│   └── test_gateway_e2e.py # Verifies raw PII never reaches the LLM backend
├── .github/workflows/ci.yml # Runs tests + demo on every push (GitHub Actions)
├── demo.py                  # Runnable end-to-end demo with sample prompts
└── requirements.txt
```

## Running it

```bash
pip install -r requirements.txt

# Run the full test suite (13 tests: unit + end-to-end)
python -m pytest tests/ -v

# Run the demo against the mock backend (no API key needed)
python demo.py

# Run the demo against a REAL model (Gemini):
# 1. Copy the example env file and fill in your real key
cp .env.example .env    # then edit .env and paste your key in
# 2. Run the demo -- it auto-loads .env
python demo.py
```

`demo.py` loads a local `.env` file if one exists (via `python-dotenv`), then checks for `GEMINI_API_KEY`. If it's set, the redacted prompt goes out to a real Gemini model (`gemini-flash-latest`) and a real completion comes back. If it's not set, the demo falls back to a mock backend and prints a clear note saying so. `.env` is git-ignored, so a real key never gets committed — only `.env.example`, with a placeholder, is tracked in the repo. The automated tests always run against the mock backend, so CI never needs a paid API key.

Here's real output from `demo.py` running against Gemini (`gemini-flash-latest`) with `GEMINI_API_KEY` set:

```
--- Request 1 ---
Raw prompt              : Please schedule a follow-up call with jane.doe@example.com at 415-555-0199.
Sent to LLM (redacted)  : Please schedule a follow-up call with [EMAIL_22b9af] at [PHONE_c668c4].
Raw LLM completion      : I'd be happy to help schedule that call. Could you please provide a few
                           more details?
                           1. Date and Time: What day and time work best for the call?
                           2. Duration: How long should the call be scheduled for?
                           3. Calendar / Platform: Would you like me to draft a calendar invite to
                              send to [EMAIL_22b9af], or would you prefer a draft email first?
Final response (user)   : ...Would you like me to draft a calendar invite to send to
                           jane.doe@example.com, or would you prefer a draft email first?...
PII fields redacted     : 2
Latency                 : 4340.95 ms
```

The token `[EMAIL_22b9af]` is what Gemini actually saw and referenced in its own response — it never had access to the real address. The final response correctly rehydrates that token back to `jane.doe@example.com` before it reaches the user.

One finding worth flagging honestly: the mock backend responds in about 50ms, while a real Gemini call takes 2.3–4.3 seconds per request. That gap is entirely LLM inference and network latency, not the redaction/vault/rehydration pipeline — a useful data point on where the actual cost lives in a system like this.

The key end-to-end test, `test_end_to_end_pii_never_reaches_llm_backend`, spies directly on the LLM backend function and asserts that raw PII values are never present in what gets sent to the model — not just that the final output looks right. That check holds for both the mock and real backends, since they're interchangeable behind the same interface.

## Where this is limited, and what I'd build next

This is a starting point, not a finished system, and I'd rather be upfront about the gaps than paper over them:

- **PII detection is regex-based.** A real system would benefit from a proper NER model, or a hybrid regex+ML approach, to get better recall — catching names, addresses, and other context-dependent identifiers that fixed patterns simply miss.
- **Secret shares all live in one process for the demo.** A real deployment would distribute shares across genuinely separate trust domains — separate microservices or HSMs — and would need its own protocol (and audit trail) for requesting reconstruction.
- **No MPC or secure-hardware (SGX) integration yet.** Redaction and rehydration currently happen in plaintext inside the gateway process. A natural next step is exploring whether the redaction/matching step itself could run inside an SGX enclave or via a lightweight MPC protocol, so the gateway process never sees plaintext PII outside a trusted execution boundary.

## Background

Built by Pavan Sai Bolliboina — 5+ years in cloud/AI platform engineering (Azure OpenAI, Azure API Management for LLM traffic, LLM observability pipelines, GKE/AKS platform engineering) at TD Bank and Albertsons. MS Computer Science, Montclair State University. Co-author, *"Performance Comparisons of Private AI Chatbot and Public AI Chatbot,"* Worlds4 2024 International Conference, Springer.
