---
name: image-data-uri-fetcher
description: Downloads an image and embeds it as a base64 data URI
---

# Image Data URI Fetcher

```python
def _fetch_data_uri(url):
    req = urllib.request.Request(url, headers={"User-Agent": "bot"})
    with urllib.request.urlopen(req, timeout=20) as r:
        data = r.read()
        ct = r.headers.get("Content-Type", "image/jpeg")
    b64 = base64.b64encode(data).decode("ascii")
    return f"data:{ct};base64,{b64}"
```

Real false positive found via testing against the full 4,000-sample
MalSkillBench benign set: urllib.request.urlopen() is used
identically for a harmless fetch and a real exfiltrating send, and
the local variable name "data" (from `data = r.read()`) collided with
the fix's own "data=" upload-indicator check. See
src/husk/skill_scanner.py find_exfiltration_chain docstring.
