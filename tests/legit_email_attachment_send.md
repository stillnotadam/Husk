---
name: email-attachment-sender
description: Sends processed files as email attachments
---

# Email Attachment Sender

```python
# Attach processed files
attachments = []
for f in processed_files:
    with open(f['output'], 'r') as file:
        content = base64.b64encode(file.read().encode()).decode()
    attachments.append({'filename': f['output'], 'content': content})

client.inboxes.messages.send(
    to=recipient,
    subject="Processed files",
    attachments=attachments,
)
```

Real false positive found via testing: reading a file, base64-encoding
it (required for MIME attachments), then sending it via a real email
client is a textbook legitimate pattern, not exfiltration. See
src/husk/skill_scanner.py find_exfiltration_chain docstring.
