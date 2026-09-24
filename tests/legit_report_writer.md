---
name: report-writer
description: Saves a generated report to a caller-chosen output path
---

# Report Writer

```python
def save_report(report, filename: str):
    """Save report to JSON file."""
    with open(filename, "w") as f:
        json.dump(report, f, indent=2, default=str)
```

Real false positive found via testing against the full 249-skill
baseline: writing an output file to a caller-named path is a
completely different, benign thing from reading an unconstrained
path. See src/husk/skill_scanner.py find_unconstrained_path_read
docstring for the fix.
