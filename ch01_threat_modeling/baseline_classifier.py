"""High-throughput baseline threat classifier.

Implements a fast n-gram token and subword model with calibrated logistic scoring.
Designed for inline execution (<1.5ms) as a pre-filter before heavy transformer inference.
Zero external dependencies required (pure Python standard library), with optional scikit-learn export.
"""
from __future__ import annotations

import math
import re
import time
from typing import Dict, List, Tuple
from .taxonomy import ThreatCategory, SeverityLevel, ThreatSignal, ThreatAssessment, CATEGORY_SEVERITY_MAP


# Known signature patterns for zero-shot heuristics
THREAT_SIGNATURES: Dict[ThreatCategory, List[Tuple[re.Pattern, float]]] = {
    ThreatCategory.PROMPT_INJECTION_DIRECT: [
        (re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|rules)", re.IGNORECASE), 0.98),
        (re.compile(r"(?i)disregard\s+(all\s+)?(previous|prior|above)?\s*(directives|system\s+prompt|guidelines|safety\s+filter|rules)", re.IGNORECASE), 0.96),
        (re.compile(r"(?i)you\s+are\s+now\s+in\s+(developer|unrestricted|god)\s+mode", re.IGNORECASE), 0.95),
        (re.compile(r"(?i)new\s+system\s+(directive|rule):\s*", re.IGNORECASE), 0.92),
        (re.compile(r"(?i)forget\s+(all\s+)?(the\s+)?rules\s+(about\s+safety)?", re.IGNORECASE), 0.94),
    ],
    ThreatCategory.PROMPT_INJECTION_INDIRECT: [
        (re.compile(r"(?i)\[system\s+notification:.*safety.*deprecated", re.IGNORECASE), 0.96),
        (re.compile(r"(?i)administrative\s+override\s+enabled", re.IGNORECASE), 0.95),
    ],
    ThreatCategory.JAILBREAK_PERSONA: [
        (re.compile(r"(?i)from\s+now\s+on\s+you\s+are\s+(DAN|STAN|DUDE|AIM|EvilConfidant)", re.IGNORECASE), 0.99),
        (re.compile(r"(?i)do\s+anything\s+now", re.IGNORECASE), 0.95),
        (re.compile(r"(?i)hypothetically\s+speaking,\s+as\s+a\s+(villain|hacker)", re.IGNORECASE), 0.88),
        (re.compile(r"(?i)pretend\s+you\s+have\s+no\s+content\s+filters", re.IGNORECASE), 0.92),
        (re.compile(r"(?i)as\s+an\s+actor\s+in\s+a\s+fictional\s+movie\s+playing\s+a\s+rogue\s+AI", re.IGNORECASE), 0.93),
    ],
    ThreatCategory.JAILBREAK_PAYLOAD_SMUGGLING: [
        (re.compile(r"(?i)decode\s+this\s+base64\s+(string|payload)", re.IGNORECASE), 0.96),
        (re.compile(r"(?i)base64-decode\s+the\s+above\s+blob", re.IGNORECASE), 0.97),
        (re.compile(r"[A-Za-z0-9+/]{24,}={0,2}", re.IGNORECASE), 0.75),
    ],
    ThreatCategory.SYSTEM_PROMPT_EXTRACTION: [
        (re.compile(r"(?i)(print|repeat|output|show|reveal)\s+(the\s+|your\s+)?(confidential|initial|system|hidden)\s+(prompt|instructions|rules)", re.IGNORECASE), 0.97),
        (re.compile(r"(?i)what\s+(was|were)\s+the\s+exact\s+words\s+above\?", re.IGNORECASE), 0.89),
        (re.compile(r"(?i)begin\s+your\s+response\s+with\s+the\s+full\s+verbatim\s+system\s+prompt", re.IGNORECASE), 0.97),
    ],
    ThreatCategory.CREDENTIAL_HARVESTING: [
        (re.compile(r"(?i)(api[_-]?key|aws[_-]?secret|bearer\s+token|private\s+key|password)\s*[:=]\s*[A-Za-z0-9_\-\.]{16,}", re.IGNORECASE), 0.95),
        (re.compile(r"(?i)output\s+the\s+(secret\s+admin\s+password|database\s+connection\s+string|aws_secret_access_key)", re.IGNORECASE), 0.96),
        (re.compile(r"(?i)give\s+me\s+(the\s+)?(api\s+keys?|passwords?|credentials?|secrets?)\s+from\s+the\s+database", re.IGNORECASE), 0.93),
    ],
    ThreatCategory.POLICY_VIOLATION: [
        (re.compile(r"(?i)tell\s+me\s+how\s+to\s+build\s+malware", re.IGNORECASE), 0.98),
        (re.compile(r"(?i)bypass\s+(our\s+)?api\s+token\s+validation", re.IGNORECASE), 0.91),
    ]
}


class FastBaselineThreatClassifier:
    """Ultra-fast regex + n-gram statistical baseline classifier."""

    def __init__(self, threshold: float = 0.5):
        self.threshold = threshold
        # Weight vectors for token n-grams
        self._feature_weights: Dict[str, float] = {
            "ignore previous": 2.5,
            "disregard directives": 2.8,
            "disregard guidelines": 2.8,
            "system prompt": 2.1,
            "confidential instructions": 2.6,
            "reveal instructions": 2.4,
            "dan": 2.9,
            "unrestricted mode": 2.7,
            "jailbreak": 3.0,
            "exfiltrate": 2.6,
            "base64 decode": 2.2,
            "base64 string": 2.0,
            "sudo mode": 2.0,
            "malware": 2.9,
            "override enabled": 2.7,
            "rogue ai": 2.5,
            "aws secret": 2.8,
        }

    def _tokenize(self, text: str) -> List[str]:
        cleaned = re.sub(r"[^\w\s]", " ", text.lower())
        return cleaned.split()

    def _extract_ngrams(self, tokens: List[str]) -> List[str]:
        ngrams = list(tokens)
        for i in range(len(tokens) - 1):
            ngrams.append(f"{tokens[i]} {tokens[i+1]}")
        return ngrams

    def predict_signals(self, text: str) -> List[ThreatSignal]:
        signals: List[ThreatSignal] = []

        # 1. Signature scan
        for category, patterns in THREAT_SIGNATURES.items():
            for pattern, base_conf in patterns:
                match = pattern.search(text)
                if match:
                    signals.append(ThreatSignal(
                        category=category,
                        severity=CATEGORY_SEVERITY_MAP.get(category, SeverityLevel.MEDIUM),
                        confidence=base_conf,
                        pattern_matched=match.group(0),
                        span_start=match.start(),
                        span_end=match.end(),
                        remediation_advice=f"Detected pattern matching known signature for {category.value}."
                    ))

        # 2. Statistical score calculation
        tokens = self._tokenize(text)
        ngrams = self._extract_ngrams(tokens)
        raw_score = 0.0
        for ng in ngrams:
            if ng in self._feature_weights:
                raw_score += self._feature_weights[ng]

        # Sigmoid calibration: 1 / (1 + e^(-(x - 2.0)))
        stat_prob = 1.0 / (1.0 + math.exp(-raw_score + 1.5)) if raw_score > 0 else 0.02
        if stat_prob > self.threshold and not signals:
            signals.append(ThreatSignal(
                category=ThreatCategory.PROMPT_INJECTION_DIRECT,
                severity=SeverityLevel.HIGH,
                confidence=round(stat_prob, 3),
                pattern_matched="statistical_ngram_density",
                remediation_advice="Statistically elevated semantic threat density."
            ))

        return signals

    def evaluate(self, text: str) -> ThreatAssessment:
        t0 = time.perf_counter()
        signals = self.predict_signals(text)
        dt_ms = (time.perf_counter() - t0) * 1000.0

        if not signals:
            return ThreatAssessment(
                is_threat=False,
                primary_category=ThreatCategory.BENIGN,
                risk_score=0.01,
                signals=[],
                latency_ms=round(dt_ms, 3),
                action_recommended="allow"
            )

        # Compute combined risk score
        max_signal = max(signals, key=lambda s: s.confidence)
        risk = max_signal.confidence
        action = "block" if risk >= 0.85 else ("quarantine" if risk >= 0.50 else "alert")

        return ThreatAssessment(
            is_threat=risk >= self.threshold,
            primary_category=max_signal.category,
            risk_score=round(risk, 4),
            signals=signals,
            latency_ms=round(dt_ms, 3),
            action_recommended=action
        )
