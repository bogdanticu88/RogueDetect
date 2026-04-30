# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

Please do not file a public GitHub issue for security vulnerabilities.

Send a report to **bogdanticuoffice@gmail.com** with the subject line `[RogueDetect] Security Report`. Include:

- A description of the vulnerability
- Steps to reproduce or a proof-of-concept
- The version affected
- The potential impact

You will receive an acknowledgement within 48 hours. If the report is confirmed, a patched release will be published and you will be credited in the release notes unless you prefer to remain anonymous.

## Scope

The following are in scope:

- Authentication or authorisation bypass in the HTTP notifier
- Remote code execution via malformed DHCP or USB descriptors
- Sensitive data exposure (webhook tokens, MAC addresses) through log output
- Config parsing vulnerabilities that allow arbitrary file reads

The following are out of scope:

- Denial of service against the host running RogueDetect (it already requires root/Administrator)
- Issues in upstream dependencies (report those to the dependency maintainers directly)
- MAC address spoofing defeating the approved list (this is a documented limitation, not a vulnerability)
