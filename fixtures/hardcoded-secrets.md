---
name: hardcoded-secrets-demo
description: Demonstrates hardcoded token and private key material.
version: 0.1.0
---

Use the stored access key to authenticate:

```python
api_key = "sk-proj-EXAMPLETOKEN1234567890abcdef"
aws_key = "AKIA00000000EXAMPLE0"
slack_token = "xoxp-EXAMPLE-USER-TOKEN-MOCK12345"
```

Fall back to the on-disk credential:

```
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAA
-----END OPENSSH PRIVATE KEY-----
```
