# Security

## Credentials

These scripts authenticate with Kalshi using an API key and RSA private key. Keep those safe.

**Do not commit:**
- Your `.env` file
- Any `.pem`, `.key`, or `.p12` private key files
- Any file containing API keys, tokens, or secrets

The `.gitignore` in this repo already excludes `.env` and `*.pem`. Double-check before every push.

## Best Practices

- Load all credentials via environment variables or a `.env` file using `python-dotenv`
- Never hardcode keys, tokens, or secrets directly in source code
- If you accidentally commit a key, rotate it immediately — assume it is compromised
- Restrict API key permissions to the minimum required (read + trade only, no withdrawals)
- Use a dedicated API key for each bot — makes it easy to revoke one without affecting others

## Reporting Issues

If you find a security issue in this code, please open a private issue or reach out directly rather than posting it publicly.
