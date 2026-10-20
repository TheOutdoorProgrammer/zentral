# 1. Keep community OIDC independent from enterprise authentication

Date: 2026-10-20

## Status

Accepted.

## Context and Problem Statement

The community deployment needs OIDC login through the existing identity provider.
Upstream core is Apache-2.0, while ee contains separately licensed features.
MDM administration requires explicit authorization independent of identity-provider login eligibility.

## Considered Options

1. Implement a separate OIDC account backend using Authlib and Apache core models.
2. Enable or adapt enterprise OIDC code.
3. Trust a reverse proxy email header.

## Decision Outcome

Chosen: **option 1**.

Implement authorization-code login with PKCE, state, nonce and signed ID-token validation. Bind accounts to exact issuer and subject, require verified email and explicit deployment allowlists, and refuse automatic linking to existing accounts. Recheck grants for each session request. Exclude ee from image and Python paths, and remove community imports/routes that depended on it.

## Consequences

### Good

- Runs using the Apache core and independently implemented authentication.
- Rejects email-based account takeover and applies grant revocation to existing sessions.
- Keeps protocol tokens out of sessions, storage and telemetry.

### Bad

- The fork must maintain authentication security and test compatibility with upstream account changes.
- Existing local accounts require an explicit migration procedure instead of automatic email linking.
- Enterprise SAML, SCIM and enterprise realm OIDC are unavailable in this runtime.

### Rejected because

- Enterprise code is outside the independently implemented Apache community scope.
- Proxy email headers cannot independently prove issuer, subject, audience and nonce and introduce a spoofing boundary.
