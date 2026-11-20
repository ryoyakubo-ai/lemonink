"""Test server that never answers requests but keeps sending notifications."""
import json
import sys
import time

for _ in range(200):
    print(json.dumps({"jsonrpc": "2.0", "method": "notifications/message", "params": {"data": "tick"}}), flush=True)
    time.sleep(0.1)
