import time
from dlp_scanner import DLPScanner

def run_benchmark():
    scanner = DLPScanner()
    # A text with many repeated sensitive-looking patterns
    # e.g., repeated AWS credentials, repeated credit cards, etc.
    text = "AKIA1234567890123456 " * 1000 + "sk-abcdefghijklmnopqrstuvwxyz " * 1000

    start_time = time.time()
    for _ in range(10):
        scanner.scan(text)
    end_time = time.time()

    print(f"Elapsed time: {end_time - start_time:.4f} seconds")

if __name__ == "__main__":
    run_benchmark()
