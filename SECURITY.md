# Security policy

Security updates apply to the 0.1.x release line.

## Report a vulnerability

Do not post passwords, tokens or exploitable vulnerability details in public issues. Use GitHub's private **Report a vulnerability** option if it is enabled, or contact the maintainers through an existing private channel. There is no dedicated security email address or guaranteed response time.

Include the version or commit, the affected component, the impact and steps to reproduce the problem using test data.

## Security features

MyDesk uses Argon2 password hashes, password strength and breach checks, expiring access tokens, rotating refresh tokens and session revocation. Device access is limited to its owner and requires a separate device password. Two-factor authentication and email recovery are available when configured.

Staging and production require HTTPS, PostgreSQL, Redis, valid secrets and enabled security checks. Keep credentials in local environment files or mounted secret files, outside Git. Back up the encryption key separately from the database; it is needed to read stored two-factor secrets and queued email.

The CI workflow runs automated tests and dependency, code and secret scans. These checks do not constitute a security certification or an independent penetration test.

See the [server guide](Server/README.md) for configuration and deployment, and the [Android guide](Android/README.md) for device setup and access controls.
