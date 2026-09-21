"""Cryptographic, Salted Token Redactor for Compliance (DPDP Act, GDPR, HIPAA).

Replaces sensitive entities with deterministic keyed pseudonyms so conversational
context is preserved while preventing raw secret leakage to LLM providers.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Dict, Tuple
from .dlp_scanner import DLPScanner, SensitiveMatch


class PIIRedactor:
    """Performs consistent, reversible or one-way tokenized redaction."""

    def __init__(self, salt: bytes = b"threat-defense-salt-2026"):
        self.salt = salt
        self.scanner = DLPScanner()
        self.token_vault: Dict[str, str] = {}  # token -> original value

    def _hash_token(self, value: str, prefix: str) -> str:
        h = hmac.new(self.salt, value.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
        return f"[{prefix}_{h}]"

    def redact(self, text: str) -> Tuple[str, Dict[str, str]]:
        """
        Redacts all sensitive entities from input text.
        Returns (redacted_text, redaction_map).
        """
        matches = self.scanner.scan(text)
        if not matches:
            return text, {}

        redacted_text = ""
        last_idx = 0
        local_map: Dict[str, str] = {}

        for m in matches:
            # Append preceding clean text
            redacted_text += text[last_idx:m.start]
            
            # Generate deterministic pseudonym token
            token = self._hash_token(m.raw_value, m.sensitive_type.value.upper())
            redacted_text += token

            local_map[token] = m.raw_value
            self.token_vault[token] = m.raw_value
            last_idx = m.end

        redacted_text += text[last_idx:]
        return redacted_text, local_map

    def restore(self, redacted_text: str) -> str:
        """Restores tokens back to original values upon model egress."""
        restored = redacted_text
        for token, original in self.token_vault.items():
            restored = restored.replace(token, original)
        return restored
