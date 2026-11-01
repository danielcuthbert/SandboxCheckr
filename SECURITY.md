# Security policy

SandboxCheckr handles process isolation, credentials, and network policy. Its
security guarantees vary by operating system and mechanism; see
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and
[`docs/SECURITY_ASSESSMENT_PLAN.md`](docs/SECURITY_ASSESSMENT_PLAN.md) for known
limits and unverified attack hypotheses.

## Reporting a vulnerability

Please report vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/danielcuthbert/sandboxcheckr/security/advisories/new)
when it is enabled for this repository. Do not include exploit details in a
public issue. If private reporting is unavailable, open a brief public issue
asking for a private reporting channel, without posting reproduction steps or
security-sensitive details.

Please include the affected version or commit, operating system and version,
SandboxCheckr mechanism and launch mode, the expected boundary, observed
behavior, and a minimal reproduction using synthetic credentials and data.
