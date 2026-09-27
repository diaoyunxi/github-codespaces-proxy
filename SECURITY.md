# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

Please report security vulnerabilities by opening a private security advisory on GitHub.

## Security Considerations

This tool creates a proxy tunnel to GitHub Codespaces. Users should:
- Never expose the local proxy port to the internet
- Use strong authentication tokens
- Verify TLS certificates
- Run in isolated environments when possible
