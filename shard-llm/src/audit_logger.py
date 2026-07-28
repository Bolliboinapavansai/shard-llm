"""
audit_logger.py

Structured, append-only audit logging for every request that passes through
the gateway. Modeled after the shape of Azure API Management's
`ApiManagementGatewayLlmLog` diagnostic schema: one JSON record per request,
capturing latency, token counts, and -- critically for this project --
how many PII fields were redacted, WITHOUT ever logging the PII values
themselves.

Each line in the log file is a self-contained JSON object (JSON Lines format),
which is easy to ship to a log aggregator (Splunk, Datadog, ELK, etc.) in a
real deployment.
"""

import json
import time
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class RequestAuditRecord:
    request_id: str
    timestamp: float
    model: str
    prompt_tokens_estimate: int
    completion_tokens_estimate: int
    pii_redactions: int
    latency_ms: float
    status: str


class AuditLogger:
    def __init__(self, log_path: str = "demo_logs/audit_log.jsonl"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_request(self, model: str, prompt: str, completion: str,
                     pii_redactions: int, latency_ms: float, status: str = "success") -> RequestAuditRecord:
        record = RequestAuditRecord(
            request_id=str(uuid.uuid4()),
            timestamp=time.time(),
            model=model,
            # Rough token estimate (word count) -- swap for a real tokenizer in production.
            prompt_tokens_estimate=len(prompt.split()),
            completion_tokens_estimate=len(completion.split()),
            pii_redactions=pii_redactions,
            latency_ms=round(latency_ms, 2),
            status=status,
        )
        with self.log_path.open("a") as f:
            f.write(json.dumps(asdict(record)) + "\n")
        return record

    def read_all(self):
        if not self.log_path.exists():
            return []
        with self.log_path.open() as f:
            return [json.loads(line) for line in f if line.strip()]
