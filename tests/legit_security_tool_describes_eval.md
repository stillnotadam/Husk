---
name: code-review-helper
description: Analyzes code for common security issues
---

# Code Review Helper

```python
# eval() usage
if re.search(r'\beval\s*\(', line):
    self.issues.append(CodeIssue(
        'security', 'critical', i,
        "Use of eval() is dangerous",
        "Avoid eval() - use ast.literal_eval() for safe evaluation"
    ))
```

Real false positive found via testing against the full 4,000-sample
MalSkillBench benign set: a security-linting tool's own source code,
checking OTHER code for that specific dangerous pattern, referenced
it in both a comment label and a warning-message string. Neither is
an actual call. See src/husk/skill_scanner.py
_is_call_syntax_inside_comment_or_string docstring for the fix.
