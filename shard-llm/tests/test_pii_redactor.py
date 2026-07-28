import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from pii_redactor import PIIVault, redact, rehydrate


def test_email_is_redacted():
    vault = PIIVault()
    text = "Contact me at test.user@example.com please."
    redacted_text, n = redact(text, vault)
    assert "test.user@example.com" not in redacted_text
    assert n == 1
    assert "[EMAIL_" in redacted_text


def test_multiple_pii_types_redacted():
    vault = PIIVault()
    text = "Email jane@company.com, call 212-555-0134, SSN 987-65-4321."
    redacted_text, n = redact(text, vault)
    assert n == 3
    assert "jane@company.com" not in redacted_text
    assert "987-65-4321" not in redacted_text


def test_no_pii_no_replacements():
    vault = PIIVault()
    text = "This sentence has no sensitive information at all."
    redacted_text, n = redact(text, vault)
    assert n == 0
    assert redacted_text == text


def test_vault_encrypt_decrypt_round_trip():
    vault = PIIVault(num_shares=5, threshold=3)
    text = "Reach jane@company.com for details."
    redacted_text, _ = redact(text, vault)

    encrypted_blob = vault.encrypt_vault()
    rebuilt_key = vault.reconstruct_key_from_shares(vault.shares[:3])

    from cryptography.fernet import Fernet
    import json
    decrypted_mapping = json.loads(Fernet(rebuilt_key).decrypt(encrypted_blob).decode("utf-8"))

    restored = rehydrate(redacted_text, decrypted_mapping)
    assert restored == text


def test_tokens_are_unique_per_occurrence():
    vault = PIIVault()
    text = "a@x.com and b@x.com are different addresses."
    redacted_text, n = redact(text, vault)
    assert n == 2
    # Two distinct emails should get two distinct tokens.
    tokens = [tok for tok in redacted_text.split() if tok.startswith("[EMAIL_")]
    assert len(set(tokens)) == 2
