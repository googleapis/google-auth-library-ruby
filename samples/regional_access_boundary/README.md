# Regional Access Boundary Sample Scripts

This directory contains sample scripts to demonstrate and verify the behavior of the Regional Access Boundary (RAB) feature in the Ruby auth library.

## How to Run the Samples

To run most samples, you need a valid Service Account JSON key file. Set the `GOOGLE_APPLICATION_CREDENTIALS` environment variable to point to your key file, and run the script using `bundle exec ruby`:

```bash
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/your/service_account.json"

bundle exec ruby samples/regional_access_boundary/default_universe.rb
```

### Samples requiring NO ambient credentials

Some samples are designed to verify that unsupported credentials (like User Credentials) correctly skip the RAB lookup. For these samples, you should **unset** the `GOOGLE_APPLICATION_CREDENTIALS` environment variable so they fall back to ambient user credentials:

*   `unsupported.rb`

```bash
unset GOOGLE_APPLICATION_CREDENTIALS

bundle exec ruby samples/regional_access_boundary/unsupported.rb
```

## What to Look For

Each sample script ends with a clear statement of success or failure. Look for lines starting with `Success!` or `Failure!`.

For example, in `unsupported.rb`:
```
Success! RAB header is not present for unsupported credentials.
```

To protect your secrets, all samples redact the `Authorization` header value in the printed output.

## Mocking and Dummy Configs

To make these samples testable without requiring complex external environments (like Azure or Okta for Workload Identity, or a slow metadata server), we used `WebMock` to mock network calls in some scripts:

*   **`workload_identity.rb` and `workforce_identity.rb`**: These use dummy JSON configuration files (`workload_identity_config.json` and `workforce_identity_config.json`) and use `WebMock` to simulate the external token source and the STS token exchange. This allows verifying the full code path for audience parsing and URL construction without real external identities.
*   **`lookup_error.rb`, `retryable_error.rb`, `malformed_response.rb`, `cooldown_recovery.rb`**: These use `WebMock` to simulate various failure modes of the IAM lookup endpoint to verify fail-open, retry, and cooldown behaviors.

### Transparency Note

While these scripts use `WebMock` to intercept network calls, they are **not fake**. They exercise the real code paths in `BaseClient`, `Fetcher`, and `Cache` exactly as they would run in production. The mocking is only used to provide predictable inputs and simulate backend responses that are difficult to recreate in a simple local environment without extensive infrastructure setup. They rightfully assert their value by providing a way to verify the complex logic stack (async fetch, cache, retries) in a reproducible way.

## Known Gaps

The following gaps in verification were identified during implementation and are tracked here for completeness (also documented in `docs/rab/GAPS.md` at the project root):

*   **Immediate Failure Logging**: In `lookup_error.rb`, we use a 500 error which triggers retries. We do not see the warning log immediately in the sample output because the script ends before retries are exhausted.
*   **Compute Engine Email Failure**: We cannot easily simulate failure to fetch the email from the metadata server in a sample script without complex mocking of `Google::Cloud.env`. This is covered by unit tests.
*   **Time-dependent behaviors**: Samples for `hard_expiry.rb` and `soft_expiry.rb` require stubbing time or waiting for hours, which is not practical in simple scripts without adding dependencies like `Timecop`. These are covered by unit tests.
*   **Impersonated Credentials Success Path**: We couldn't easily verify the success path for `ImpersonatedServiceAccountCredentials` (actually attaching the header) in a sample script because it requires a complex IAM setup for impersonation. This is covered by unit tests.
