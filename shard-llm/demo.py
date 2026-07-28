"""
demo.py

Run this to see the full pipeline end-to-end on a few example prompts.
    python3 demo.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from gateway import PrivacyPreservingGateway

EXAMPLE_PROMPTS = [
    "Please schedule a follow-up call with jane.doe@example.com at 415-555-0199.",
    "Update the customer record for John Smith, SSN 123-45-6789, card 4111 1111 1111 1111.",
    "The support ticket came in from IP 10.0.0.42, contact back at support@acme.io.",
    "No sensitive data in this one -- just summarize our Q3 roadmap.",
]


def main():
    gateway = PrivacyPreservingGateway(model="gpt-4o-demo")

    print("=" * 78)
    print("PRIVACY-PRESERVING LLM GATEWAY -- END-TO-END DEMO")
    print("=" * 78)

    for i, prompt in enumerate(EXAMPLE_PROMPTS, start=1):
        print(f"\n--- Request {i} ---")
        result = gateway.handle_request(prompt)
        print(f"Raw prompt              : {result['raw_prompt']}")
        print(f"Sent to LLM (redacted)  : {result['redacted_prompt_sent_to_llm']}")
        print(f"Raw LLM completion      : {result['llm_raw_completion']}")
        print(f"Final response (user)   : {result['final_response_to_user']}")
        print(f"PII fields redacted     : {result['pii_redactions']}")
        print(f"Latency                 : {result['latency_ms']} ms")

    print("\n" + "=" * 78)
    print("AUDIT LOG (demo_logs/audit_log.jsonl) -- note: NO raw PII values appear")
    print("=" * 78)
    for record in gateway.audit.read_all():
        print(json.dumps(record))


if __name__ == "__main__":
    main()
