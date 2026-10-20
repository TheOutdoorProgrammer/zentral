# SCEP integration acceptance

This manual integration test verifies a real deployed certificate authority through Zentral's SCEP proxy before enabling device enrollment. It uses the same Smallstep SCEP implementation pinned by step-ca v0.30.2, generates an ephemeral RSA key, and never writes the key or challenge to disk.

Build with `go build -o /tmp/zentral-scep-smoke .`. Supply one JSON object on standard input containing `url`, `host`, `root_file`, `challenge`, `common_name`, `organization`, and `serial_number`. The challenge must have been minted for that exact synthetic subject, no SANs, and key usage 5. Stream it directly from the authenticated broker or a privileged management session. Never put the challenge in arguments, logs, Git, or a saved fixture.

Use a loopback HTTP port-forward to the public web listener while its public enrollment routes remain blocked. `host` selects an allowed Django hostname. `root_file` is the public CA root PEM used to verify both GetCACert and the issued leaf. The probe follows no redirects and accepts plaintext HTTP only on 127.0.0.1.

GetCACert must provide a trusted chain with digital-signature and RSA key-encipherment capabilities, either in one certificate or separate signing and encryption certificates. Only RSA certificates permitting key encipherment are used as PKCSReq encryption recipients. A CA chain with only certificate-signing and CRL-signing usage is rejected before requesting a certificate. Go issuance previously succeeded with that chain, while Apple's SCEP parser rejected it before sending a CSR. These checks cover that known compatibility gap; they do not replace native Apple validation or an actual device enrollment. See Apple's [`SecSCEPValidateCACertMessage` and RA candidate selection](https://github.com/apple-oss-distributions/Security/blob/main/OSX/sec/Security/SecSCEP.c).

Acceptance requires four real PKCSReq exchanges:

1. An altered subject is denied without consuming the valid challenge.
2. The expected subject receives a certificate with the expected key, chain, key usage and client-authentication purpose.
3. An identical request can retry successfully.
4. An altered subject is still denied after the challenge has been bound.

Only bounded pass/fail results are printed. Use a synthetic subject that cannot identify a real enrollment session. Remove the synthetic challenge after verification; its private key is discarded when the process exits. The test proves certificate issuance and rejection, not actual iPhone enrollment or APNs delivery.

## Native Apple certificate-response validation

On macOS, build the separate diagnostic and provide a saved public GetCACert CMS response:

```sh
clang -Wall -Wextra -Werror -framework CoreFoundation -framework Security apple/main.c -o /tmp/zentral-apple-scep-validate
/tmp/zentral-apple-scep-validate /path/to/getcacert.der
```

The diagnostic calls the host Security framework's CMS decoder and `SecSCEPValidateCACertMessage` through dynamically resolved symbols. It prints only status codes, certificate count and selection booleans; exit zero means validation succeeded. Missing private symbols, malformed CMS and invalid SCEP certificates fail with nonzero exit codes. A shared signing/encryption certificate can succeed with `separate_encryption_selected` false.

This exercises the actual installed macOS implementation and requires no trust-store changes. It uses no CA fingerprint, matching the current OTA payload, and does not establish an independent trust anchor. The Go probe separately verifies the chain against the supplied root. These private Apple symbols can change or disappear across OS versions; a macOS result does not prove behavior on every iOS version or complete device enrollment. This diagnostic is intentionally outside the Go package and Ubuntu CI.
