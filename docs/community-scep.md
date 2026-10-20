# Community SCEP broker

The community deployment uses a dedicated Smallstep CA and one-time enrollment challenges to issue device identity certificates. The broker preserves Zentral's native IDent issuer payload and secret engine. It does not require the commercial issuer.

Run the normal public web application on port 8000 and a separate process using `server.scep_wsgi` on port 8001. The internal WSGI URLconf exposes only `GET /healthz/`, `POST /internal/mdm/scep/challenges/`, and `POST /internal/mdm/scep/authorize/`. The public URLconf has no internal routes. Separate workers are required: a public enrollment request calls the broker, and a public SCEP request calls the CA, which calls the broker back.

Configure the native IDent issuer URL as `http://127.0.0.1:8001/internal/mdm/scep/challenges/`, with a strong bearer token matching `ZENTRAL_SCEP_BROKER_TOKEN` (at least 32 characters). Only the local application may reach the mint listener. Route the private HTTPS CA callback to port 8001 and deny internal paths on the public hostname. The public SCEP URL is `/public/mdm/scep/`; it proxies only supported SCEP operations to `https://localhost:9000/scep/zentral`, trusting `/etc/zentral-ca/root_ca.crt`. TLS verification cannot be disabled or redirected through configuration.

Configure a Smallstep v0.30.2 `SCEPCHALLENGE` webhook for provisioner `zentral`. Supply its generated ID as `ZENTRAL_SCEP_WEBHOOK_ID` and its base64 signing key as `ZENTRAL_SCEP_WEBHOOK_SECRET`. The broker validates the webhook ID, exact-body HMAC-SHA256 signature, and timestamp within five minutes. No static public challenge is accepted.

Each mint creates a random 256-bit challenge with a 15-minute lifetime. The database contains only its digest, encrypted expected CSR configuration, expiry, and the digests binding its first accepted CSR and transaction. A row lock makes concurrent first use atomic. Identical transport retries are accepted before expiry; any changed key, CSR, or transaction is rejected. The default secret engine must encrypt, including when an administrator gives a cleartext engine a different name. Preserve the existing Fernet password and Django secret-key recovery material.

Run `python server/manage.py cleanup_scep_challenges` hourly. It removes expired records in bounded batches, retaining active challenges. Monitor the scheduled job so sensitive encrypted enrollment metadata does not accumulate.

The initial policy accepts RSA keys from 2048 through 8192 bits, exact subject and SAN values, and IDent `key_usage: 5`. The CA template must fix certificate key usage to digital signature plus key encipherment and extended key usage to client authentication. Apple documents Key Usage as an issuance setting without guaranteeing a CSR extension. Consequently, an omitted CSR KeyUsage is accepted under that fixed policy; a present extension must match exactly. Requests for CA capability, another extended usage, unsupported extensions, or extra SANs are rejected. This conservative policy is intentionally not a general certificate issuance service.

Request and response sizes are bounded. The proxy forwards neither browser credentials nor cookies, follows no redirects, and accepts only SCEP response content types. Broker and proxy spans use static names, operation categories, and outcomes. Existing HTTP instrumentation exports methods and status only; it never exports the SCEP query string, CSR, subject, challenge, transaction, or certificate.

Disable raw Gunicorn, Django request, reverse-proxy, and CA access logs for these endpoints. SCEP permits carrying the certificate request in a GET query. Sanitized application telemetry provides operation and failure visibility without those request targets.

Primary protocol references: [Smallstep webhook request types](https://github.com/smallstep/certificates/blob/v0.30.2/webhook/types.go), [Smallstep webhook signing](https://github.com/smallstep/certificates/blob/v0.30.2/authority/provisioner/webhook.go), and [Apple SCEP payload](https://developer.apple.com/documentation/devicemanagement/scep).
