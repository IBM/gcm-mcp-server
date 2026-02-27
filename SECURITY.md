# Security Policy

## Reporting Security Vulnerabilities

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in this project, please report it privately to help us address it responsibly.

### How to Report

1. **Email:** ashrivastava@ibm.com
2. **Subject:** [SECURITY] GCM MCP Server - Brief Description
3. **Include:**
   - Type of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if available)

### Response Timeline

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 5 business days
- **Resolution:** Varies by severity (critical issues prioritized)

### Security Best Practices

When deploying this project:

1. **Credentials Management**
   - Never commit API tokens, passwords, or secrets to version control
   - Use environment variables for sensitive data
   - Rotate GCM credentials and OIDC client secrets regularly

2. **Network Security**
   - Run containers in isolated networks
   - Use SSL/TLS for GCM connections (`GCM_VERIFY_SSL=true`)
   - Bind HTTP server to localhost (`127.0.0.1`) when not needed externally

3. **Access Control**
   - Use GCM credentials with minimum required permissions
   - Implement rate limiting for API endpoints
   - Monitor and audit tool execution logs

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Known Security Considerations

- This is a development/demonstration project (MVP status)
- Not recommended for production use without thorough security review
- HTTP (SSE) endpoints require a valid API key (`Authorization: Bearer <key>` header)
- Admin endpoints (`/admin/*`) are restricted to localhost only
- Logs may contain sensitive GCM data

## Disclaimer

This code is provided as-is under the Apache 2.0 license. IBM makes no warranties regarding security and is under no obligation to provide security updates or support.
