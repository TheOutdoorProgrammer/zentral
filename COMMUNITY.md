# Community deployment

This fork adds independently implemented OpenID Connect authentication to Zentral's Apache-2.0 core. Use it when you operate your own identity provider and need explicit administrator grants without enterprise authentication code.

The source history still contains upstream's separately licensed `ee/` directory. The community image excludes that directory, the Python path does not load it, and community realm registration excludes enterprise OIDC, SAML and SCIM. This implementation does not grant rights to enterprise code.

## Authentication

Register a confidential OIDC client with the exact callback `https://YOUR_HOST/accounts/oidc/callback/`. The provider must support authorization code, S256 PKCE, `client_secret_basic`, discovery and asymmetric ID-token signatures. ID tokens must contain a verified email. Supply configuration through environment variables and a secret manager:

| Variable | Meaning |
| --- | --- |
| `ZENTRAL_OIDC_ISSUER` | Exact HTTPS issuer, including any trailing slash advertised by discovery |
| `ZENTRAL_OIDC_CLIENT_ID` | Registered client ID |
| `ZENTRAL_OIDC_CLIENT_SECRET` | Confidential client secret |
| `ZENTRAL_OIDC_REDIRECT_URI` | Exact registered HTTPS callback |
| `ZENTRAL_OIDC_ALLOWED_EMAILS` | Comma-separated exact verified emails allowed to sign in |
| `ZENTRAL_OIDC_ADMIN_EMAILS` | Subset of allowed emails granted administrator access |
| `ZENTRAL_OIDC_LABEL` | Login button label |
| `ZENTRAL_OIDC_ONLY` | Set `true` to disable the local password login form and endpoint |

Empty grants deny everyone. Domain-wide grants are unsupported. Accounts bind to `(issuer, subject)`. Matching an existing account's email never links or replaces that account. Changing the issuer or an existing subject's email requires an explicit operator migration after verifying identity ownership. Non-administrators receive no additional policy grants automatically.

Login validates state, a five-minute flow deadline, nonce, signature, issuer, audience and token expiry. PKCE binds the token exchange to the browser session. Tokens are discarded after the callback. Each session request rechecks account activation and current email/admin grants. Restart processes after changing environment configuration.

Retain an independently secured operator recovery path before enabling OIDC-only mode. A rollback must retain the identity table and migration history; do not roll back the database merely to revert an application image.

## Build and verify

Python 3.14 and PostgreSQL are required. Create a virtual environment and install `requirements.txt`. With an isolated PostgreSQL database named `zentral_test`:

```sh
export ZENTRAL_CONF_DIR="$PWD/tests/community_conf"
export POSTGRES_HOST=127.0.0.1 POSTGRES_PORT=5432 POSTGRES_USER=zentral_test
export ZENTRAL_POLICIES_SYNC=0 ZENTRAL_PROBES_SYNC=0 ZENTRAL_STORES_SYNC=0 ZENTRAL_QUIET=1
python server/manage.py test tests.server_accounts.test_community_oidc tests.server_accounts.test_auth_backend tests.server_base.test_telemetry
npm ci
node --test tests/browser-telemetry.test.mjs
npm run build
docker build --build-arg APP_ENV=community --build-arg APP_VERSION="$(git rev-parse HEAD)" .
```

Migrate before starting the application. Provision configured event stores after their dependencies become healthy. The upstream deployment configuration remains necessary for PostgreSQL, queues, stores and enabled modules.

## Observability

Set `OTEL_EXPORTER_OTLP_ENDPOINT` to a private OTLP HTTP/protobuf receiver, `OTEL_SERVICE_NAME`, and `OTEL_RESOURCE_ATTRIBUTES` containing `service.version` and `deployment.environment.name`. Supply any OTLP authorization header through secrets, never browser configuration. `OTEL_PROPAGATION_HOSTS` is an exact host allowlist for outgoing W3C context propagation.

Set `FARO_COLLECTOR_URL` to a Faro application collector URL with an explicit production origin allowlist. The browser bundle uses `@nerdswhofish/browser-telemetry`. Application telemetry exports bounded request routes, operations, outcomes and trace correlation, excluding raw messages, exception details, request contents, SQL, account identities and authentication tokens. Unfiltered sidecar logs must not be forwarded as application logs.

## Deployment scope

The operator console and its OIDC authentication are independent of Apple enrollment activation. APNs credentials, SCEP, signed device callbacks and enrollment workflows require separate configuration and validation. Do not expose an MDM endpoint that trusts externally supplied certificate identity headers. Public ingress must strip those headers.

Pin deployments to an image digest. Back up PostgreSQL and stateful event-store data before upgrades. Review upstream changes to authentication, realm imports, migrations and telemetry hooks when rebasing this fork.
