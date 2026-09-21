.PHONY: test test-python test-go bench clean run-gateway run-onnx

PYTHON ?= python3
GO ?= go

test: test-python test-go

test-python:
	$(PYTHON) tests/run_all_checks.py

test-go:
	cd ch05_golang_gateway && $(GO) test -v -race ./...

bench:
	$(PYTHON) ch04_onnx_serving/latency_bench.py
	$(PYTHON) ch06_adversarial_evals/testbed_eval.py

build-go:
	cd ch05_golang_gateway && $(GO) build -o ../bin/threat-gateway ./cmd/gateway

run-gateway: build-go
	./bin/threat-gateway -port 8080 -upstream http://localhost:8000

run-onnx:
	$(PYTHON) ch04_onnx_serving/onnx_runtime_server.py --port 8000

clean:
	rm -rf bin/ *.pyc __pycache__ .pytest_cache runs/
