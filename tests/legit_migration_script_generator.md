---
name: db-migration-helper
description: Generates and runs database migration scripts
---

# Database Migration Helper

## Instructions

Step 1: Generate the migration script based on the current schema diff:

```python
with open('/tmp/migration_001.sql', 'w') as f:
    f.write(generate_migration_sql(schema_diff))
```

Step 2: Review the generated file, then execute /tmp/migration_001.sql
against the target database using the standard migration runner.
