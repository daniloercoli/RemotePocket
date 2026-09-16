# Security policy

Security updates apply to the 0.1.x release line.

## Report a vulnerability

Do not post passwords, tokens or exploitable vulnerability details in public issues. Use GitHub's private **Report a vulnerability** option if it is enabled, or contact the maintainers through an existing private channel. There is no dedicated security email address or guaranteed response time.

Include the version or commit, the affected component, the impact and steps to reproduce the problem using test data.

## Security features

MyDesk uses Argon2 password hashes, password strength and breach checks, expiring access tokens, rotating refresh tokens and session revocation. Device access is limited to its owner and requires a separate device password. Two-factor authentication and email recovery are available when configured.

Login denials use the same public response for incorrect credentials, missing users, locked accounts and inactive accounts. Every attempt performs an Argon2 check; detailed failures remain in the audit trail. Public self-registration still reveals username/email availability through success versus duplicate-registration responses. Registration rate limits restrict this exposure but do not eliminate account enumeration.

Device session starts use PBKDF2-SHA-256 and the HMAC proof construction from SCRAM-SHA-256. The server stores salted verifiers and accepts each challenge once, within 60 seconds, on its original console connection. See the [device authentication protocol](Server/docs/device-authentication.md) for its scope and transport requirements.

Staging and production require HTTPS, PostgreSQL, Redis, valid secrets and enabled security checks. Keep credentials in local environment files or mounted secret files, outside Git. Back up the encryption key separately from the database; it is needed to read stored two-factor secrets and queued email.

The CI workflow runs automated tests and dependency, code and secret scans. These checks do not constitute a security certification or an independent penetration test.

See the [server guide](Server/README.md) for configuration and deployment, and the [Android guide](Android/README.md) for device setup and access controls.
