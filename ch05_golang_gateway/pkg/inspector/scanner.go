package inspector

import (
	"encoding/json"
	"regexp"
	"strings"
)

// ThreatSignal represents a detected security threat signal in Go.
type ThreatSignal struct {
	Category   string  `json:"category"`
	Severity   string  `json:"severity"`
	Confidence float64 `json:"confidence"`
	Pattern    string  `json:"pattern"`
}

// InspectionResult holds the outcome of inspecting an incoming payload.
type InspectionResult struct {
	IsThreat       bool           `json:"is_threat"`
	ExtractedText  string         `json:"extracted_text"`
	RiskScore      float64        `json:"risk_score"`
	MatchedSignals []ThreatSignal `json:"matched_signals"`
}

// Pre-compiled high-speed regex signatures for inline pre-filtering (<0.1ms).
var signatures = []struct {
	category string
	severity string
	regex    *regexp.Regexp
}{
	{
		category: "prompt_injection_direct",
		severity: "high",
		regex:    regexp.MustCompile(`(?i)ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|directives|rules)`),
	},
	{
		category: "jailbreak_persona",
		severity: "high",
		regex:    regexp.MustCompile(`(?i)(from\s+now\s+on\s+you\s+are\s+DAN|you\s+are\s+in\s+developer\s+mode|do\s+anything\s+now)`),
	},
	{
		category: "system_prompt_extraction",
		severity: "high",
		regex:    regexp.MustCompile(`(?i)(print|repeat|reveal|show)\s+(the\s+)?(initial|system|hidden)\s+(prompt|instructions)`),
	},
	{
		category: "credential_harvesting",
		severity: "critical",
		regex:    regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16}|sk-[a-zA-Z0-9]{20,})`),
	},
}

// ExtractPrompt extracts prompt text from plain strings or OpenAI-compatible JSON payloads.
func ExtractPrompt(body []byte) string {
	var parsed struct {
		Prompt   string `json:"prompt"`
		Messages []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}

	if err := json.Unmarshal(body, &parsed); err == nil {
		if parsed.Prompt != "" {
			return parsed.Prompt
		}
		var parts []string
		for _, m := range parsed.Messages {
			if m.Role == "user" {
				parts = append(parts, m.Content)
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "\n")
		}
	}

	return string(body)
}

// FastScan executes low-latency regex signature matching against extracted text.
func FastScan(text string) InspectionResult {
	var signals []ThreatSignal
	maxConf := 0.0

	for _, sig := range signatures {
		if loc := sig.regex.FindString(text); loc != "" {
			conf := 0.95
			if conf > maxConf {
				maxConf = conf
			}
			signals = append(signals, ThreatSignal{
				Category:   sig.category,
				Severity:   sig.severity,
				Confidence: conf,
				Pattern:    loc,
			})
		}
	}

	isThreat := len(signals) > 0
	return InspectionResult{
		IsThreat:       isThreat,
		ExtractedText:  text,
		RiskScore:      maxConf,
		MatchedSignals: signals,
	}
}
