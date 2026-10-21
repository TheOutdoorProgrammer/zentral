# 2. Serve device-scoped family onboarding inside the community MDM application

Date: 2026-10-21

## Status

Accepted.

## Context and Problem Statement

Family devices need guided setup after supervised enrollment, including managed app installation and manual account, AutoFill, and family settings. Children should not need MDM administrator accounts. The existing application already owns the authoritative device state and privacy-filtered telemetry.

## Considered Options

1. Integrate a device-scoped web app into the community MDM application
2. Deploy a separate web service with an MDM API credential
3. Build and distribute a native iOS app

## Decision Outcome

Chosen: **option 1**.

Use the existing Django application, a small mobile web interface, and a Web Clip scoped to one enrolled device. A random 256-bit bearer capability travels in the URL fragment and is exchanged over a CSRF-protected POST for a Secure HttpOnly cookie. Persist only its digest in the access record; the managed profile necessarily retains the capability. Bind access to the current enrollment certificate so an old link cannot regain access after erase and re-enrollment. An administrator explicitly chooses the audience and publishes the isolated profile. Revoke on demand and reject access after expiry, checkout, blocking, loss of supervision, or blueprint change. Read native effective artifact scope and device-reported statuses; persist manual confirmations separately. Do not expose device commands or administrator credentials to this capability.

## Consequences

### Good

- Reuses deployment, authoritative device data, backups and privacy-safe telemetry without a general MDM API credential.
- Requires no native signing pipeline or child administrator account.
- Clearly distinguishes installed configuration from personal setup and functional checks.

### Bad

- Possession of a copied setup link permits reading that device's limited setup status and changing its confirmations until expiry or revocation; it is not cryptographic hardware authentication.
- Per-device credential-bearing profiles require runtime provisioning outside OpenTofu and renewal after expiry.
- Cannot bypass Apple's required user approvals or verify third-party account sign-in.

### Rejected because

- A separate service adds a credential boundary and operational dependency without a current functional need.
- A native app adds provisioning, signing and distribution maintenance while retaining the same user-consent limitations.
