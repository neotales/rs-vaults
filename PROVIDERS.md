# Listing and removal by provider

`Client::list_secrets`, `list_certificates`, and `list_keys` return names, not
values. Each list is scoped to the configured vault. Check `Client::supports`
for the operation and resource type before calling it. A successful removal
means the provider accepted that operation; it does not promise secure erasure
of backups or storage remnants. Removal is never automatically retried.
Provider-specific options go in `RemoveOptions::query`; unsupported options
are rejected.

| Provider | Listing | Default removal | `purge` and `version` |
| --- | --- | --- | --- |
| OS credentials | Unsupported: account identifiers hash the original names. | Deletes a secret. | Both are unsupported. |
| KeePass | Root secret titles and marked certificate/key groups; duplicate titles fail. | Moves the entry to the recycle bin when enabled; otherwise deletes it and records a tombstone. Writes require opt-in. | Purge removes an active or uniquely matching recycled entry and records a tombstone; versions are unsupported. |
| age JSON, age SQLite, local JSON | Secrets, certificates and keys; includes names marked deleted. | Marks the selected or latest version deleted. | Purge removes one version, or the entire resource and history without a version. Purging the latest does not reactivate older versions. |
| Vault/OpenBao KV v2 | Recursive secret paths. | Soft-deletes the selected or latest version. | Purge destroys a specified version or deletes the metadata and all versions when no version is specified. |
| Infisical | Shared secret names in the configured folder, excluding imports. | Deletes the shared secret; an approval response is not reported as completed deletion. | Both are unsupported by the driver's v4 API. |
| Vaultwarden/Bitwarden | Login-password item UUIDs from the CLI cache. | Moves the login to trash; writes require opt-in. | Purge permanently deletes the active or trashed item; versions are unsupported. |
| AWS Secrets Manager | Secret names across pages. | Schedules whole-secret deletion with the provider's recovery window. | Purge requests deletion without recovery; final deletion is asynchronous. Individual versions cannot be deleted. `removal_with_recovery_days` configures a 7–30 day window and cannot be combined with purge. |
| Azure Key Vault | Secret names across pages. | Soft-deletes the whole secret. | Purge deletes an **already soft-deleted** secret and can be blocked by purge protection. Individual versions cannot be deleted. |
| Google Secret Manager | Secret IDs across pages. | Deletes the entire secret if no version is specified; this is irreversible. With a version, disables it. | Purge of a version requests destruction, which may be delayed by the secret's configured policy. `removal_with_etag` sets a precondition. |

The cloud providers implement secrets only; their certificate and key
operations are unsupported. `local-crypto` and `crypto` are utilities, not
vault drivers.

Provider references:

- [Vault KV v2 API](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2)
- [Infisical list](https://infisical.com/docs/api-reference/endpoints/secrets/list)
  and [delete](https://infisical.com/docs/api-reference/endpoints/secrets/delete)
- [Bitwarden CLI](https://bitwarden.com/help/cli/#delete)
- [AWS DeleteSecret](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_DeleteSecret.html)
- [Azure Key Vault soft delete and purge protection](https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview)
- [Google Secret Manager delayed destruction](https://cloud.google.com/secret-manager/docs/delay-destruction-of-secret-versions)
