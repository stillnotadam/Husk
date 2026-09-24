---
name: queue-worker-loop
description: A worker thread that pulls from a queue and processes forever
---

# Queue Worker Loop

```python
def _process_queue(self):
    while True:
        batch_meta = self.queue.get()
        response = requests.get("http://api.example.com/data")
```

Real false positive found via testing against the full 249-skill
baseline: queue.get() is a blocking call that naturally paces the
loop, a legitimate worker-thread pattern with no CPU spinning. See
src/husk/skill_scanner.py find_unbounded_cpu_loop docstring for the fix.
