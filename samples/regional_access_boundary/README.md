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

## Live vs Mocked Execution

To align with the **RAB Manual Testing Guide**, the samples are structured as follows:

### Live Samples (Real-World Credentials Required)

These samples require valid configurations and credentials. They perform live network requests against Google Cloud APIs to retrieve tokens and regional access boundaries:

*   **`default_universe.rb` & `regional_endpoint.rb`**: Require Service Account credentials (set via `GOOGLE_APPLICATION_CREDENTIALS`).
*   **`impersonated.rb`**: Requires Impersonated Service Account credentials.
*   **`workload_identity.rb` & `workforce_identity.rb`**: Require Workload Identity / Workforce Identity credentials respectively (set via `GOOGLE_APPLICATION_CREDENTIALS`).

### Mocked Samples (Error and Resiliency Handling)

To trigger error conditions, DNS timeouts, malformed responses, or force specific timing states (like cache cooldowns) without depending on Google Cloud infrastructure failures, the following scripts use `WebMock` to intercept and mock the IAM `allowedLocations` endpoint:

*   **`lookup_error.rb`**: Mocks a 400 error to verify that the client fails open (the main API request succeeds).
*   **`retryable_error.rb`**: Mocks 50x errors to verify that the client retries the lookup for 1 minute before entering cooldown.
*   **`malformed_response.rb`**: Mocks an empty location response to verify that it fails open and enters cooldown.
*   **`cooldown_recovery.rb`**: Mocks a failure followed by recovery to verify that the client resumes lookups after the cooldown expires.

While these scripts use `WebMock` to intercept network calls, they exercise the real code paths in `BaseClient`, `Fetcher`, and `Cache` exactly as they run in production.

## Known Gaps

The following gaps in verification were identified during implementation and are tracked here for completeness (also documented in `docs/rab/GAPS.md` at the project root):

*   **Immediate Failure Logging**: In `lookup_error.rb`, we use a 500 error which triggers retries. We do not see the warning log immediately in the sample output because the script ends before retries are exhausted.
*   **Compute Engine Email Failure**: We cannot easily simulate failure to fetch the email from the metadata server in a sample script without complex mocking of `Google::Cloud.env`. This is covered by unit tests.
*   **Time-dependent behaviors**: Samples for `hard_expiry.rb` and `soft_expiry.rb` require stubbing time or waiting for hours, which is not practical in simple scripts without adding dependencies like `Timecop`. These are covered by unit tests.
*   **Impersonated Credentials Success Path**: We couldn't easily verify the success path for `ImpersonatedServiceAccountCredentials` (actually attaching the header) in a sample script because it requires a complex IAM setup for impersonation. This is covered by unit tests.
