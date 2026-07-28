import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from gateway import PrivacyPreservingGateway, mock_llm_call


def test_end_to_end_pii_never_reaches_llm_backend():
    """
    The core security property of this project: verify that the
    text actually handed to the LLM backend function never contains
    the raw PII, only redaction tokens.
    """
    seen_by_llm = {}

    def spy_backend(model, prompt):
        seen_by_llm["prompt"] = prompt
        return mock_llm_call(model, prompt)

    gateway = PrivacyPreservingGateway(llm_backend=spy_backend)
    raw = "Please contact jane.doe@example.com or 415-555-0199 about her SSN 123-45-6789."
    result = gateway.handle_request(raw)

    assert "jane.doe@example.com" not in seen_by_llm["prompt"]
    assert "415-555-0199" not in seen_by_llm["prompt"]
    assert "123-45-6789" not in seen_by_llm["prompt"]
    assert result["pii_redactions"] == 3


def test_end_to_end_final_response_is_rehydrated():
    gateway = PrivacyPreservingGateway()
    raw = "Follow up with jane.doe@example.com."
    result = gateway.handle_request(raw)
    assert "jane.doe@example.com" in result["final_response_to_user"]


def test_audit_log_never_contains_raw_pii():
    gateway = PrivacyPreservingGateway()
    raw = "Reach out to secret.person@example.com immediately."
    gateway.handle_request(raw)

    records = gateway.audit.read_all()
    assert len(records) >= 1
    for record in records:
        assert "secret.person@example.com" not in str(record)
