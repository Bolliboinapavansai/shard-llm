"""
gateway.py

The end-to-end privacy-preserving LLM gateway. Ties together:
    1. pii_redactor.py   -- detect + tokenize PII, encrypt the vault
    2. secret_sharing.py -- protect the vault's encryption key (via pii_redactor)
    3. audit_logger.py   -- structured, PII-free observability logging
    4. a pluggable LLM backend (mocked here; swap in a real provider call)

This mirrors, at small scale, the pattern used in production LLM platforms:
an API gateway sits between the caller and the model provider, enforcing
policy (here: PII redaction) and emitting observability data, without the
model provider ever seeing raw sensitive data.
"""

import time
from typing import Callable, Dict, Tuple

from audit_logger import AuditLogger
from pii_redactor import PIIVault, redact, rehydrate


def mock_llm_call(model: str, prompt: str) -> str:
    """
    Stand-in for a real LLM provider call (e.g., Azure OpenAI / Anthropic API).
    Swap this out for a real HTTP call in a production deployment --
    the rest of the pipeline (redaction, vault, audit log) is unchanged.
    """
    # Simulate network + inference latency.
    time.sleep(0.05)
    return (
        f"[mock-{model} response] Thanks, I've noted the details for "
        f"{_first_token_mentioned(prompt)} and will follow up shortly."
    )


def _first_token_mentioned(prompt: str) -> str:
    import re
    match = re.search(r"\[[A-Z_]+_[0-9a-f]{6}\]", prompt)
    return match.group(0) if match else "the contact"


class PrivacyPreservingGateway:
    def __init__(self, model: str = "gpt-4o-demo",
                 llm_backend: Callable[[str, str], str] = mock_llm_call,
                 threshold: int = 3, num_shares: int = 5):
        self.model = model
        self.llm_backend = llm_backend
        self.audit = AuditLogger()
        self.threshold = threshold
        self.num_shares = num_shares

    def handle_request(self, raw_prompt: str) -> Dict:
        start = time.perf_counter()

        # 1. Create a fresh vault + secret-shared key for this request.
        vault = PIIVault(num_shares=self.num_shares, threshold=self.threshold)

        # 2. Redact PII before anything leaves our trust boundary.
        redacted_prompt, n_redactions = redact(raw_prompt, vault)

        # 3. Call the LLM with the redacted prompt only.
        completion = self.llm_backend(self.model, redacted_prompt)

        # 4. Encrypt vault, then simulate reconstructing the key from shares
        #    (in production, shares would live with separate custodians).
        encrypted_vault = vault.encrypt_vault()
        key_shares_used = vault.shares[: self.threshold]
        rebuilt_key = vault.reconstruct_key_from_shares(key_shares_used)

        from cryptography.fernet import Fernet
        import json
        decrypted_mapping = json.loads(Fernet(rebuilt_key).decrypt(encrypted_vault).decode("utf-8"))

        # 5. Rehydrate PII in the response (never sent to the LLM provider).
        final_response = rehydrate(completion, decrypted_mapping)

        latency_ms = (time.perf_counter() - start) * 1000

        # 6. Audit log -- structured, PII-free.
        record = self.audit.log_request(
            model=self.model,
            prompt=redacted_prompt,
            completion=completion,
            pii_redactions=n_redactions,
            latency_ms=latency_ms,
        )

        return {
            "raw_prompt": raw_prompt,
            "redacted_prompt_sent_to_llm": redacted_prompt,
            "llm_raw_completion": completion,
            "final_response_to_user": final_response,
            "pii_redactions": n_redactions,
            "latency_ms": round(latency_ms, 2),
            "audit_request_id": record.request_id,
        }


if __name__ == "__main__":
    gateway = PrivacyPreservingGateway()
    result = gateway.handle_request(
        "Please schedule a follow-up call with jane.doe@example.com at 415-555-0199."
    )
    for k, v in result.items():
        print(f"{k}: {v}")
