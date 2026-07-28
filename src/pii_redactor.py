"""
pii_redactor.py

Detects common PII patterns in text (emails, phone numbers, SSNs, credit
card numbers, IP addresses) and replaces them with reversible tokens
before the text is sent to an LLM provider.

The mapping from token -> original value ("the vault") is encrypted at
rest using a symmetric key (Fernet / AES-128-CBC + HMAC). That key is
never stored directly -- it only ever exists in memory after being
reconstructed from Shamir secret-shares (see secret_sharing.py).

Flow:
    raw_prompt
        -> detect PII spans via regex
        -> replace each span with a random opaque token, e.g. [PII_7f3a1c]
        -> store {token: original_value} in an in-memory dict
        -> encrypt the dict with the reconstructed vault key -> vault.bin
        -> send the *redacted* prompt to the LLM
        -> when the LLM response references a token, rehydrate it back
           to the original value using the decrypted vault (never sent
           to the LLM provider itself)
"""

import json
import re
import secrets
from base64 import urlsafe_b64encode
from typing import Dict, Tuple

from cryptography.fernet import Fernet

from secret_sharing import reconstruct_secret, split_secret

# --- PII pattern definitions -------------------------------------------------
# These are intentionally simple, explainable regexes (not a production-grade
# NER/PII model) -- the point of this repo is to demonstrate the *pipeline*
# and secure-key-handling pattern, not to claim state-of-the-art PII recall.
PII_PATTERNS = {
    "EMAIL": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "PHONE": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "IPV4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}


class PIIVault:
    """
    Holds the encrypted token->original-value mapping and manages the
    encryption key's lifecycle via Shamir secret sharing.
    """

    def __init__(self, num_shares: int = 5, threshold: int = 3):
        # 1. Generate a fresh Fernet key for this session's vault.
        raw_key = Fernet.generate_key()  # 32 url-safe base64 bytes
        self._fernet = Fernet(raw_key)

        # 2. Split the raw key into N shares (K-of-N reconstruction).
        key_as_int = int.from_bytes(raw_key, byteorder="big")
        self.shares = split_secret(key_as_int, num_shares=num_shares, threshold=threshold)
        self.threshold = threshold
        self._key_len_bytes = len(raw_key)

        # In-memory mapping, only ever persisted in encrypted form.
        self._mapping: Dict[str, str] = {}

    def reconstruct_key_from_shares(self, shares_subset) -> bytes:
        """Demonstrates that >= threshold shares can rebuild the exact same Fernet key."""
        recovered_int = reconstruct_secret(shares_subset)
        return recovered_int.to_bytes(self._key_len_bytes, byteorder="big")

    def add(self, token: str, original_value: str) -> None:
        self._mapping[token] = original_value

    def encrypt_vault(self) -> bytes:
        payload = json.dumps(self._mapping).encode("utf-8")
        return self._fernet.encrypt(payload)

    def decrypt_vault(self, encrypted_blob: bytes) -> Dict[str, str]:
        payload = self._fernet.decrypt(encrypted_blob)
        return json.loads(payload.decode("utf-8"))


def redact(text: str, vault: PIIVault) -> Tuple[str, int]:
    """
    Replace all detected PII spans in `text` with opaque tokens.
    Returns (redacted_text, number_of_replacements).
    """
    redacted = text
    count = 0
    for label, pattern in PII_PATTERNS.items():
        def _replace(match: re.Match) -> str:
            nonlocal count
            token = f"[{label}_{secrets.token_hex(3)}]"
            vault.add(token, match.group(0))
            count += 1
            return token

        redacted = pattern.sub(_replace, redacted)
    return redacted, count


def rehydrate(text: str, decrypted_mapping: Dict[str, str]) -> str:
    """Replace tokens like [EMAIL_ab12cd] back with their original values."""
    result = text
    for token, original in decrypted_mapping.items():
        result = result.replace(token, original)
    return result


if __name__ == "__main__":
    vault = PIIVault(num_shares=5, threshold=3)
    sample = (
        "Hi, please reach out to jane.doe@example.com or call 415-555-0199. "
        "Her SSN on file is 123-45-6789 and she connected from 10.0.0.42."
    )

    redacted_text, n = redact(sample, vault)
    print("Original :", sample)
    print("Redacted :", redacted_text)
    print(f"Replacements made: {n}")

    encrypted_blob = vault.encrypt_vault()
    print("\nEncrypted vault (never leaves our infra):", encrypted_blob[:40], "...")

    # Simulate reconstructing the key later from only 3 of 5 shares
    subset = vault.shares[0:3]
    rebuilt_key = vault.reconstruct_key_from_shares(subset)
    rebuilt_fernet = Fernet(rebuilt_key)
    decrypted_mapping = json.loads(rebuilt_fernet.decrypt(encrypted_blob).decode("utf-8"))

    restored = rehydrate(redacted_text, decrypted_mapping)
    print("\nRestored :", restored)
    print("Round-trip successful:", restored == sample)
