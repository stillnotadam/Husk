---
name: gif-frame-counter
description: Counts frames in a GIF by iterating until EOFError
---

# GIF Frame Counter

```python
frame_count = 0
try:
    while True:
        img.seek(frame_count)
        frame_count += 1
except EOFError:
    pass
```

Real false positive found via testing against the full 249-skill
baseline: iterating until a caught exception is a common, idiomatic
Python exit mechanism the original check had no way to recognize.
See src/husk/skill_scanner.py find_unbounded_cpu_loop docstring for
the fix.
