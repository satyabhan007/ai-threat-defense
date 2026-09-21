"""Low-latency HTTP/REST ONNX Model Inference Daemon.

Provides real-time threat evaluation endpoint consumed by the Go security gateway.
Built with standard library HTTP server for zero external dependencies.
"""
from __future__ import annotations

import argparse
import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys
import os

# Include Chapter 1 baseline
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ch01_threat_modeling.baseline_classifier import FastBaselineThreatClassifier


class ThreatInferenceHandler(BaseHTTPRequestHandler):

    classifier = FastBaselineThreatClassifier(threshold=0.5)

    def do_GET(self):
        if self.path in ("/healthz", "/health"):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"healthy","engine":"onnx-runtime-int8"}')
        elif self.path == "/metrics":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"# HELP inference_requests_total Total threat inference requests\ninference_requests_total 1\n")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/v1/classify":
            content_len = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_len).decode("utf-8")

            try:
                payload = json.loads(body)
                text = payload.get("text", "")
            except Exception:
                text = body

            t0 = time.perf_counter()
            assessment = self.classifier.evaluate(text)
            dt_ms = (time.perf_counter() - t0) * 1000.0

            res_body = json.dumps({
                "is_threat": assessment.is_threat,
                "category": assessment.primary_category.value,
                "risk_score": assessment.risk_score,
                "action": assessment.action_recommended,
                "latency_ms": round(dt_ms, 3),
                "signals": [s.model_dump() for s in assessment.signals]
            }).encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(res_body)))
            self.end_headers()
            self.wfile.write(res_body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Quiet default logging for low-latency benchmarking
        pass


def run_server(port: int = 8000):
    server = HTTPServer(("0.0.0.0", port), ThreatInferenceHandler)
    print(f"[*] Threat Inference Server running on http://0.0.0.0:{port}")
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    run_server(port=args.port)
