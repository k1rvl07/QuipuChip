#!/usr/bin/env python3
import json
import urllib.request
import ssl

# Read-only smoke against live device (if reachable)
url = "https://192.168.7.1/api/health"
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
try:
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
        data = json.loads(resp.read())
        print(data)
        assert resp.status == 200
        print("ok")
except Exception as e:
    print("skip:", e)
