---
name: parameterized-query-builder
description: Builds a parameterized database query the safe way
---

# Parameterized Query Builder

```python
def build_query():
    return "SELECT name FROM users WHERE id = %s"

def build_greeting(name):
    return f"Hello, {name}! Welcome to the app."
```
