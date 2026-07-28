# Privacy-Preserving LLM Gateway

[![CI](https://github.com/Bolliboinapavansai/shard-llm/actions/workflows/ci.yml/badge.svg)](https://github.com/Bolliboinapavansai/shard-llm/actions/workflows/ci.yml)

> **Proof it works:** 13 automated tests (unit + end-to-end), including a
> test that inspects exactly what text is sent to the LLM backend and
> asserts raw PII is never present in it — not just that the final output
> looks correct. Run `python -m pytest tests/ -v` or `python demo.py`
> yourself to see it live. The badge above reflects the current status on
> every push (via GitHub Actions).

A small, fully-tested reference implementation of a **secure LLM request
gateway**: it detects and redacts PII before a prompt reaches an LLM
provider, protects the redaction mapping using a **secret-shared encryption
key** (Shamir's Secret Sharing), and emits **structured, PII-free audit
logs** for observability.

This repo is intentionally scoped small (~350 lines across 4 modules) so
that every design decision can be read and understood in one sitting. The
goal is to demonstrate the *pipeline and secure-key-handling pattern*
end-to-end, not to claim state-of-the-art PII recall or production-grade
cryptography.

## Why this project

I've spent the last several years building production LLM infrastructure
in an enterprise banking environment — an Azure API Management gateway in
front of Azure OpenAI deployments, enforcing rate limits, auth, and routing
across model versions, plus an observability pipeline publishing token
usage, latency, and prompt/response logs for compliance auditability.

That work raised a question I couldn't fully answer inside a bank's
existing compliance tooling: **how do you get the observability and
auditability enterprise LLM platforms need, without ever letting sensitive
data reach the model provider or sit in a log in plaintext?** This repo is
a small, self-contained attempt to prototype one answer to that question,
combining:

- **Cloud/platform engineering** (the gateway pattern, structured
  observability) — directly from my production APIM/LLM-observability work
- **Secure computation** (Shamir secret sharing to protect the vault key,
  reversible tokenization instead of destructive redaction) — the area I'm
  looking to go deeper into for PhD research

## Architecture

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

### Why Shamir's Secret Sharing for the vault key?

A single stored decryption key is a single point of compromise — anyone
with access to that key (or the service holding it) can decrypt every
PII vault. Splitting the key into `N` shares with a reconstruction
threshold `K` means:

- No individual share reveals any information about the key
  (information-theoretic security, not just computational).
- Compromising fewer than `K` shares/custodians gives an attacker nothing.
- In a real deployment, the `K` shares would be held by separate
  services, HSMs, or on-call engineers — modeling a realistic
  multi-party trust boundary instead of "one admin holds the master key."

This repo demonstrates the mechanism (`src/secret_sharing.py`) and its
integration into a working pipeline (`src/pii_redactor.py`,
`src/gateway.py`), with unit tests verifying both the reconstruction
property and that sub-threshold shares do *not* reveal the secret.

## Design Q&A

Questions likely to come up when discussing this project — answered
explicitly here rather than left implicit in the code.

**Q: If someone obtains 2 of the 5 key shares, can they read any part of the vault?**

No. This is the core property of Shamir's Secret Sharing that
distinguishes it from "just split the password into pieces": with fewer
than the threshold (3 of 5 here), the remaining shares are consistent
with *every possible key value*, not a narrowed-down set of likely
values. This is **information-theoretic security** — not "hard to
crack," but mathematically impossible to extract any information from,
regardless of computing power. Contrast this with, e.g., knowing 2 of 4
digits of a PIN, which meaningfully narrows the search space; Shamir
shares below threshold narrow nothing.

**Q: Why not just use a single password/key instead of secret sharing?**

A single key is a single point of compromise: whoever holds it (a
person, a config file, a server) can decrypt everything, and
compromising that one thing compromises the whole vault. Splitting the
key means an attacker needs to compromise `K` independent locations
simultaneously — in a real deployment, `K` separate services or
custodians rather than one admin holding a master key. It trades "one
lock, one key" for "one lock, K-of-N keyholders must agree," which is
closer to how multi-signature vault access works in banking.

**Q: What's the actual weakness in the PII detection, and how would you fix it?**

It's regex-based, so it only catches PII matching a fixed pattern
(an `@` and domain for emails, `XXX-XX-XXXX` for SSNs, etc.). It has no
understanding of context or meaning, so it misses anything that doesn't
fit a hard-coded pattern: names, home addresses, informally-phrased
phone numbers, or company-specific identifiers. The fix is a hybrid
approach: keep regex for cheap, 100%-reliable matching on well-defined
formats (SSNs, emails, credit cards), and layer a **Named Entity
Recognition (NER) model** on top to catch the context-dependent PII
regex structurally cannot — which is how production PII detection
systems are actually built.

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

# Run the interactive demo
python demo.py
```

Example output from `demo.py`:

```
Raw prompt              : Please schedule a follow-up call with jane.doe@example.com at 415-555-0199.
Sent to LLM (redacted)  : Please schedule a follow-up call with [EMAIL_044851] at [PHONE_f72e0d].
Raw LLM completion      : [mock-gpt-4o-demo response] Thanks, I've noted the details for [EMAIL_044851]...
Final response (user)   : [mock-gpt-4o-demo response] Thanks, I've noted the details for jane.doe@example.com...
PII fields redacted     : 2
Latency                 : 52.73 ms
```

The key end-to-end test (`test_end_to_end_pii_never_reaches_llm_backend`)
asserts, by spying on the LLM backend function directly, that raw PII
values are never present in what's sent to the model — not just that the
final output looks correct.

## Current limitations (and what I'd build next)

This is a starting point, not a finished system, and I want to be
explicit about the gaps:

- **PII detection is regex-based.** A real system would benefit from a
  proper NER model or a hybrid regex+ML approach for higher recall
  (e.g., catching names, addresses, and context-dependent identifiers
  that fixed patterns miss).
- **The LLM call is mocked.** Swapping `mock_llm_call` for a real
  provider call (Azure OpenAI, Anthropic API) is a small, isolated
  change — the redaction/vault/audit pipeline around it doesn't need
  to change.
- **Secret shares live in one process for the demo.** A real deployment
  would distribute shares across genuinely separate trust domains
  (e.g., separate microservices or HSMs), and would need a protocol for
  requesting reconstruction (with its own audit trail).
- **No MPC or secure-hardware (SGX) integration yet** — the redaction
  and rehydration happen in plaintext within the gateway process. A
  natural next step is exploring whether the redaction/matching step
  itself could run inside an SGX enclave or via a lightweight MPC
  protocol, so that even the gateway process never sees plaintext PII
  outside a trusted execution boundary.

## Background

Built by Pavan Sai Bolliboina — 5+ years in cloud/AI platform engineering
(Azure OpenAI, Azure API Management for LLM traffic, LLM observability
pipelines, GKE/AKS platform engineering) at TD Bank and Albertsons.
MS Computer Science, Montclair State University. Co-author,
*"Performance Comparisons of Private AI Chatbot and Public AI Chatbot,"*
Worlds4 2024 International Conference, Springer.
