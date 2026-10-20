# SCEP integration acceptance

This manual integration test verifies a real deployed certificate authority through Zentral's SCEP proxy before enabling device enrollment. It uses the same Smallstep SCEP implementation pinned by step-ca v0.30.2, generates an ephemeral RSA key, and never writes the key or challenge to disk.

Build with `go build -o /tmp/zentral-scep-smoke .`. Supply one JSON object on standard input containing `url`, `host`, `root_file`, `challenge`, `common_name`, `organization`, and `serial_number`. The challenge must have been minted for that exact synthetic subject, no SANs, and key usage 5. Stream it directly from the authenticated broker or a privileged management session. Never put the challenge in arguments, logs, Git, or a saved fixture.

Use a loopback HTTP port-forward to the public web listener while its public enrollment routes remain blocked. `host` selects an allowed Django hostname. `root_file` is the public CA root PEM used to verify both GetCACert and the issued leaf. The probe follows no redirects and accepts plaintext HTTP only on 127.0.0.1.

Acceptance requires four real PKCSReq exchanges:

1. An altered subject is denied without consuming the valid challenge.
2. The expected subject receives a certificate with the expected key, chain, key usage and client-authentication purpose.
3. An identical request can retry successfully.
4. An altered subject is still denied after the challenge has been bound.

Only bounded pass/fail results are printed. Use a synthetic subject that cannot identify a real enrollment session. Remove the synthetic challenge after verification; its private key is discarded when the process exits. The test proves certificate issuance and rejection, not actual iPhone enrollment or APNs delivery.
