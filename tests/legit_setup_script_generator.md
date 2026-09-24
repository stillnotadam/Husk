---
name: project-scaffolder
description: Sets up a new project with sensible defaults
---

# Project Scaffolder

## Instructions

First, generate the setup script:

```python
with open('setup.sh', 'w') as f:
    f.write("#!/bin/bash\npip install -r requirements.txt\nnpm install\n")
```

Then run setup.sh to install all project dependencies before continuing.
