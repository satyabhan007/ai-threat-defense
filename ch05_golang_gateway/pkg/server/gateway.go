package server

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"github.com/satyabhan007/ai-threat-defense/ch05_golang_gateway/pkg/inspector"
	"github.com/satyabhan007/ai-threat-defense/ch05_golang_gateway/pkg/policy"
)

type Gateway struct {
	upstreamURL *url.URL
	proxy       *httputil.ReverseProxy
	policy      *policy.PolicyEngine
	AuthToken   string
}

func NewGateway(upstream string, authToken string) (*Gateway, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	return &Gateway{
		upstreamURL: u,
		proxy:       httputil.NewSingleHostReverseProxy(u),
		policy:      policy.NewPolicyEngine(),
		AuthToken:   authToken,
	}, nil
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy","service":"go-threat-gateway"}`))
		return
	}

	if g.AuthToken != "" {
		authHeader := r.Header.Get("Authorization")
		expectedAuth := "Bearer " + g.AuthToken
		if subtle.ConstantTimeCompare([]byte(authHeader), []byte(expectedAuth)) != 1 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"unauthorized"}`))
			return
		}
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, `{"error":"unable to read request body"}`, http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	start := time.Now()
	prompt := inspector.ExtractPrompt(bodyBytes)
	scanResult := inspector.FastScan(prompt)
	decision := g.policy.Evaluate(scanResult)
	dt := time.Since(start)

	w.Header().Set("X-Threat-Latency-Us", fmt.Sprintf("%d", dt.Microseconds()))
	w.Header().Set("X-Threat-Decision", string(decision.Action))

	if !decision.ShouldProxy {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(decision.HTTPStatus)
		resp, _ := json.Marshal(map[string]interface{}{
			"error":      "SecurityPolicyViolation",
			"action":     decision.Action,
			"reason":     decision.Reason,
			"risk_score": scanResult.RiskScore,
			"signals":    scanResult.MatchedSignals,
			"latency_us": dt.Microseconds(),
		})
		w.Write(resp)
		return
	}

	g.proxy.ServeHTTP(w, r)
}
