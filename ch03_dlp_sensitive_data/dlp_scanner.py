"""High-throughput Data Loss Prevention (DLP) & Secret Scanner.

Detects and classifies sensitive data patterns, credentials, PII, and source code exfiltration
prior to model ingestion or downstream API egress. Uses entropy scoring to verify secrets.
"""
from __future__ import annotations

import enum
import math
import re
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class SensitiveType(str, enum.Enum):
    API_KEY = "api_key"
    AWS_CREDENTIAL = "aws_credential"
    PRIVATE_KEY = "private_key"
    PII_EMAIL = "pii_email"
    PII_PHONE = "pii_phone"
    PII_AADHAAR = "pii_aadhaar"
    PII_PAN = "pii_pan"
    PII_SSN = "pii_ssn"
    CREDIT_CARD = "credit_card"
    HIGH_ENTROPY_SECRET = "high_entropy_secret"


class SensitiveMatch(BaseModel):
    sensitive_type: SensitiveType
    raw_value: str
    redacted_placeholder: str
    start: int
    end: int
    confidence: float = Field(ge=0.0, le=1.0)
    entropy_score: Optional[float] = None


# Production regex patterns for credential & PII detection
DLP_PATTERNS: Dict[SensitiveType, re.Pattern] = {
    SensitiveType.AWS_CREDENTIAL: re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
    SensitiveType.API_KEY: re.compile(r"\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|xox[baprs]-[0-9a-zA-Z]{10,})\b"),
    SensitiveType.PRIVATE_KEY: re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    SensitiveType.PII_EMAIL: re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
    SensitiveType.PII_PHONE: re.compile(r"(?:\+?(\d{1,3}))?[-. ]?\(?(\d{3})\)?[-. ]?(\d{3})[-. ]?(\d{4})\b"),
    SensitiveType.PII_AADHAAR: re.compile(r"\b[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}\b"),
    SensitiveType.PII_PAN: re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"),
    SensitiveType.PII_SSN: re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    SensitiveType.CREDIT_CARD: re.compile(r"\b(?:\d{4}[- ]?){3}\d{4}\b"),
}


def shannon_entropy(text: str) -> float:
    """Calculates Shannon entropy of string in bits per character."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq: Dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class DLPScanner:
    """Fast regex and Shannon entropy scanner for DLP policy enforcement."""

    def __init__(self, min_secret_entropy: float = 3.5):
        self.min_secret_entropy = min_secret_entropy

    def scan(self, text: str) -> List[SensitiveMatch]:
        matches: List[SensitiveMatch] = []

        for stype, pattern in DLP_PATTERNS.items():
            for m in pattern.finditer(text):
                val = m.group(0)
                entropy = shannon_entropy(val)
                conf = 0.95

                # Entropy check for API keys/tokens to reduce false positives
                if stype in (SensitiveType.API_KEY, SensitiveType.AWS_CREDENTIAL):
                    if entropy < self.min_secret_entropy:
                        continue
                    conf = min(1.0, 0.70 + (entropy / 8.0))

                placeholder = f"[{stype.value.upper()}_REDACTED]"
                matches.append(SensitiveMatch(
                    sensitive_type=stype,
                    raw_value=val,
                    redacted_placeholder=placeholder,
                    start=m.start(),
                    end=m.end(),
                    confidence=round(conf, 3),
                    entropy_score=round(entropy, 2)
                ))

        return sorted(matches, key=lambda x: x.start)
