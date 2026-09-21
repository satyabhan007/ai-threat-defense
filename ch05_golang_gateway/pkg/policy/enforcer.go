package policy

import "github.com/satyabhan007/ai-threat-defense/ch05_golang_gateway/pkg/inspector"

// Action represents the gateway enforcement action.
type Action string

const (
	ActionAllow      Action = "ALLOW"
	ActionBlock      Action = "BLOCK"
	ActionQuarantine Action = "QUARANTINE"
	ActionAudit      Action = "AUDIT"
)

// PolicyEngine evaluates threat assessments against organizational risk thresholds.
type PolicyEngine struct {
	BlockThreshold      float64
	QuarantineThreshold float64
}

// NewPolicyEngine returns default policy engine (Block >= 0.85, Quarantine >= 0.50).
func NewPolicyEngine() *PolicyEngine {
	return &PolicyEngine{
		BlockThreshold:      0.85,
		QuarantineThreshold: 0.50,
	}
}

// Decision represents the final enforcement verdict for a request.
type Decision struct {
	Action      Action `json:"action"`
	Reason      string `json:"reason"`
	HTTPStatus  int    `json:"http_status"`
	ShouldProxy bool   `json:"should_proxy"`
}

// Evaluate determines whether the request should proceed to upstream LLM.
func (pe *PolicyEngine) Evaluate(result inspector.InspectionResult) Decision {
	if !result.IsThreat || result.RiskScore < pe.QuarantineThreshold {
		return Decision{
			Action:      ActionAllow,
			Reason:      "Payload verified safe.",
			HTTPStatus:  200,
			ShouldProxy: true,
		}
	}

	if result.RiskScore >= pe.BlockThreshold {
		return Decision{
			Action:      ActionBlock,
			Reason:      "Request blocked: High-confidence prompt injection or security policy violation.",
			HTTPStatus:  403,
			ShouldProxy: false,
		}
	}

	return Decision{
		Action:      ActionQuarantine,
		Reason:      "Request flagged for secondary audit.",
		HTTPStatus:  429,
		ShouldProxy: false,
	}
}
