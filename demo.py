"""
demo.py

Run this to see the full pipeline end-to-end on a few example prompts.
    python3 demo.py

If the GEMINI_API_KEY environment variable is set, this uses a real
Gemini model as the LLM backend. Otherwise it falls back to the mock
backend and prints a note explaining how to enable a real one.
"""

import json
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

load_dotenv()  # reads .env in the project root, if present, into os.environ

from src .gateway import PrivacyPreservingGateway, mock_llm_call, real_gemini_llm_call

EXAMPLE_PROMPTS = [
    "Please schedule a follow-up call with jane.doe@example.com at 415-555-0199.",
    "Update the customer record for John Smith, SSN 123-45-6789, card 4111 1111 1111 1111.",
    "The support ticket came in from IP 10.0.0.42, contact back at support@acme.io.",
    "No sensitive data in this one -- just summarize our Q3 roadmap.",
]


def main():
    if os.environ.get("GEMINI_API_KEY"):
        model_name = "gemini-flash-latest"
        gateway = PrivacyPreservingGateway(model=model_name, llm_backend=real_gemini_llm_call)
        print(f"[Using REAL model: {model_name} via Gemini API]\n")
    else:
        model_name = "gpt-4o-demo"
        gateway = PrivacyPreservingGateway(model=model_name, llm_backend=mock_llm_call)
        print(
            "[No GEMINI_API_KEY found -- using MOCK backend.]\n"
            "[Set GEMINI_API_KEY to run this against a real model instead.]\n"
        )

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