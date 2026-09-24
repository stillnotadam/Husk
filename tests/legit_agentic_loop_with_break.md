---
name: agentic-tool-loop
description: A legitimate agentic loop that keeps calling tools until done
---

# Agentic Tool Loop

```python
while True:
    response = client.messages.create(
        model="claude-opus-5",
        max_tokens=16000,
        tools=tools,
        messages=messages
    )

    # If Claude is done (no more tool calls), break
    if response.stop_reason == "end_turn":
        break
```

Real false positive found via testing against the full 249-skill
baseline: a blank line inside the loop body broke the body-capture
regex, truncating it before reaching the real break statement. See
src/husk/skill_scanner.py find_unbounded_cpu_loop docstring for the fix.
