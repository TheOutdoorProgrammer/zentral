# Family Setup

Family Setup guides someone through the remaining work after their iPhone or iPad enrolls in MDM. Use it to distinguish
configuration that the device reports installed from personal steps such as account sign-in, Password AutoFill, and
checking that a VPN actually works. It is part of the community Django application and uses the existing database,
deployment, backup and telemetry infrastructure.

## Publish a device's checklist

1. Deploy this version, build its frontend assets and run the normal database migrations.
2. Sign in as a Zentral superuser. Open **MDM → Devices**, select the exact enrolled device and check its serial number.
3. Choose **Prepare Family Setup**. The device must be an active, supervised ADE iPhone or iPad with a blueprint.
4. Choose **Adult** or **Child**, matching its blueprint. Confirm the selected device, then publish.
5. Follow the setup-profile link to check delivery. Publishing sends one native APNs notification; delivery still needs
   the phone to reach Apple and Zentral. Publication is not proof that the icon has arrived.
6. Open **Family Setup** on that device's Home Screen. Its private link activates only that device's checklist.

The administrative page is `/mdm/devices/<device-id>/family-setup/`. The app itself is
`/public/mdm/family-setup/`. Visiting the app without current device access shows a pairing explanation, not a list of
devices or a login to the management console.

Publishing creates a dedicated inventory tag, Profile artifact and immutable version. Both the version and blueprint
attachment default to shard zero and target only that tag at 100. The transaction checks native effective eligibility
across the blueprint before committing. Reused tags or broadened attachments cause publication to fail. Do not change
those objects into shared Adult/Child policies. These credential-bearing profiles belong in runtime storage, outside
Git, OpenTofu and provider state.

## What the checklist knows

- The device's display name, configured audience and last MDM check-in time.
- Its currently eligible artifact versions and device-reported installation status. Only `Installed` is shown as
  installed; acknowledgement, old versions and queued work do not count as delivery of the current version.
- Missing scoped Wi-Fi, VPN and Child web-filter profiles are explicitly shown as not configured.
- Personal confirmations saved by the person using this checklist. These do not change MDM state.

The app does not inspect passwords, account sign-in, browsing history or location, and cannot issue device commands.
It cannot verify internet access or tunnel routing from an installation report. If a required app is not assigned to
the device at all, it will not appear in the native artifact list; the app-opening step explicitly calls out missing
apps for an administrator to resolve. Check signing and license eligibility separately.

There are no background push actions or automatic polling. The refresh control reads current server state. The UI
shows report timestamps, a warning for old check-ins, and preserves visibly stale data when a refresh fails. Manual
completion is presented separately from MDM installation readiness.

## Shared shortcuts

An administrator can configure approved iCloud shortcut links in the Zentral configuration:

```json
{
  "family_setup": {
    "shortcuts": [
      {
        "title": "Example shortcut",
        "url": "https://www.icloud.com/shortcuts/00000000000000000000000000000000"
      }
    ]
  }
}
```

Replace the example with a real reviewed sharing link. Only canonical HTTPS iCloud Shortcuts links are accepted.
No shortcuts are configured by default. The UI explains that state and does not pretend anything has installed.
Adding a shortcut, approving permissions and setting up its automation remain on-device actions.

## Access, renewal and recovery

The setup capability contains 256 random bits. The browser immediately removes it from the URL fragment before
initializing telemetry, then exchanges it through a CSRF-protected POST. The cookie is Secure, HttpOnly, SameSite
Strict, scoped to the setup path and lasts at most 30 days. Reopening the managed icon can establish another browser
session until the underlying access expires after 180 days.

The access record stores a SHA-256 digest. The managed profile necessarily contains the original capability; protect
profile downloads and database backups as credentials. A copied link permits reading that device's limited status and
editing its confirmations. This is a limited bearer grant, not proof of physical possession of the phone. It provides
no administrator authority, VPN keys, raw serials, UDIDs, artifact error details or management commands.

Access fails after expiry, revocation, checkout, blocking, loss of supervision, blueprint change or enrollment
certificate change. The certificate binding prevents a pre-erase link from becoming valid again after re-enrollment.
A certificate renewal may also require publishing fresh setup access. Renew from the same administrator page; it adds
a new profile version, keeps payload identities stable, and invalidates all older links and cookies immediately.
The phone must receive the new profile before its icon works again. Confirmations survive ordinary renewal, but reset
when the enrollment certificate or audience changes.

**Revoke** takes effect immediately without waiting for a device check-in. It leaves the icon installed. Removing the
artifact attachment is a separate MDM action. **Forget access on this browser** clears only the browser cookie; it does
not revoke the managed link or delete saved progress. A blueprint transfer requires deliberate reconciliation of the
existing exclusive artifact before reissuing access.

No copy of the generated link needs to be exported for recovery. Use the normal encrypted application/database backup,
or revoke and publish a replacement if access is lost. Retain published profile versions for audit and recovery.

## Tests and deployment acceptance

Run `tests.mdm.test_family_setup` with the community MDM test configuration and an isolated PostgreSQL test database.
It covers token scope, CSRF, revocation, certificate changes, current artifact status, exclusive profile eligibility,
renewal and administrator authorization. Run `npm run build` and the existing browser telemetry tests as well.

Test the actual UI at phone, tablet and desktop widths, including unpaired, pending, failed, stale, complete and offline
states. Check keyboard operation and reduced motion. Use synthetic devices in development, never production credentials
in fixture screenshots or browser recordings.

The backend emits bounded `family_setup.*` operations and correlated logs through the existing OTLP pipeline. Browser
RUM uses the existing Faro application with a fixed route allowlist. Request bodies, fragments, cookies, device names,
identifiers, step values and profile contents must never enter telemetry. Before claiming a production rollout complete,
verify real page activity in Faro, corresponding backend traces/logs, exporter health and device-reported profile delivery.

The database migration is additive. A source rollback can leave the new table in place; revoke access before retiring
the feature, and remove its managed profiles deliberately. See [the architecture decision](adr/0002-serve-device-scoped-family-onboarding-inside-the-community-m.md).
