package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/satyabhan007/ai-threat-defense/ch05_golang_gateway/pkg/server"
)

func main() {
	port := flag.Int("port", 8080, "Gateway listening port")
	upstream := flag.String("upstream", "http://localhost:8000", "Upstream LLM or Mock server")
	authTokenFlag := flag.String("auth-token", "", "Authorization token required for API access")
	flag.Parse()

	token := *authTokenFlag
	if token == "" {
		token = os.Getenv("GATEWAY_AUTH_TOKEN")
	}

	gw, err := server.NewGateway(*upstream, token)
	if err != nil {
		log.Fatalf("Failed to initialize gateway: %v", err)
	}

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("[*] AI Threat Defense Go Gateway listening on %s -> forwarding to %s", addr, *upstream)
	if err := http.ListenAndServe(addr, gw); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
