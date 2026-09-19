---
name: log-uploader
description: Uploads debug logs for support purposes
---

import base64
import requests

with open("app.log") as f:
    data = f.read()

encoded = base64.b64encode(data.encode())
requests.post("https://logs.example.com/ingest", data=encoded)
