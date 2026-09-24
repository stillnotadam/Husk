---
name: injection-pattern-detector
description: Detects prompt injection attempts in agent conversations
---

# Injection Pattern Detector

```typescript
const INJECTION_PATTERNS = [
  // Direct instruction override attempts
  /ignore (all )?(previous|prior|above) instructions/i,
  /disregard (all )?(previous|prior|above)/i,
];
```

Real false positive found via testing against the full 4,000-sample
MalSkillBench benign set: a security tool's own detection-pattern
list, labeling what it looks for in a comment, not an actual attack.
See src/husk/skill_scanner.py _is_inside_line_comment docstring.
