"""Threat taxonomy and categorization schemas for AI and LLM security.

Defines standard vulnerability classes aligned with OWASP Top 10 for LLMs (2025/2026)
and MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems).
"""
from __future__ import annotations

import enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ThreatCategory(str, enum.Enum):
    """Primary attack vectors targeting LLMs and autonomous agents."""
    BENIGN = "benign"
    PROMPT_INJECTION_DIRECT = "prompt_injection_direct"
    PROMPT_INJECTION_INDIRECT = "prompt_injection_indirect"
    JAILBREAK_PERSONA = "jailbreak_persona"
    JAILBREAK_PAYLOAD_SMUGGLING = "jailbreak_payload_smuggling"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    DATA_EXFILTRATION_PII = "data_exfiltration_pii"
    CREDENTIAL_HARVESTING = "credential_harvesting"
    MALICIOUS_TOOL_CALL = "malicious_tool_call"
    POLICY_VIOLATION = "policy_violation"


class SeverityLevel(str, enum.Enum):
    """Enforcement severity tier determining gateway action."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatSignal(BaseModel):
    """Fine-grained threat indicator detected within input or output."""
    category: ThreatCategory
    severity: SeverityLevel
    confidence: float = Field(ge=0.0, le=1.0, description="Calibrated confidence score [0.0, 1.0]")
    pattern_matched: Optional[str] = None
    span_start: Optional[int] = None
    span_end: Optional[int] = None
    remediation_advice: str = ""


class ThreatAssessment(BaseModel):
    """Comprehensive verdict produced by inline model or gateway."""
    is_threat: bool
    primary_category: ThreatCategory
    risk_score: float = Field(ge=0.0, le=1.0, description="Normalized risk score [0.0 - 1.0]")
    signals: List[ThreatSignal] = Field(default_factory=list)
    latency_ms: float = 0.0
    action_recommended: str = "allow"  # allow, block, redact, quarantine, alert

    def to_dict(self) -> Dict:
        return self.model_dump()


# Pre-defined severity mapping for standard categories
CATEGORY_SEVERITY_MAP: Dict[ThreatCategory, SeverityLevel] = {
    ThreatCategory.BENIGN: SeverityLevel.LOW,
    ThreatCategory.PROMPT_INJECTION_DIRECT: SeverityLevel.HIGH,
    ThreatCategory.PROMPT_INJECTION_INDIRECT: SeverityLevel.CRITICAL,
    ThreatCategory.JAILBREAK_PERSONA: SeverityLevel.HIGH,
    ThreatCategory.JAILBREAK_PAYLOAD_SMUGGLING: SeverityLevel.CRITICAL,
    ThreatCategory.SYSTEM_PROMPT_EXTRACTION: SeverityLevel.HIGH,
    ThreatCategory.DATA_EXFILTRATION_PII: SeverityLevel.CRITICAL,
    ThreatCategory.CREDENTIAL_HARVESTING: SeverityLevel.CRITICAL,
    ThreatCategory.MALICIOUS_TOOL_CALL: SeverityLevel.CRITICAL,
    ThreatCategory.POLICY_VIOLATION: SeverityLevel.MEDIUM,
}
