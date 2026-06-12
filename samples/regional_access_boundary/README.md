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

## Running Workload Identity (AWS) Locally

When verifying AWS Workload Identity Federation (`workload_identity.rb`), you can run the test locally on your workstation by fetching the temporary AWS credentials from the remote AWS EC2 instance, as supported by [aws_credentials.rb](https://github.com/googleapis/google-auth-library-ruby/blob/main/lib/googleauth/external_account/aws_credentials.rb):

1. SSH into the AWS EC2 VM (via the GCE VM) as per the guide:
   ```bash
   gcloud compute ssh <GCE_INSTANCE_NAME> --project=<PROJECT_ID> --zone=<GCP_ZONE> -- -L 5000:localhost:5000
   # (then inside GCE VM)
   ssh -i ~/.ssh/id_rsa_aws ec2-user@<EC2_IP_ADDRESS>
   ```
2. Retrieve the temporary security credentials using `curl` inside the EC2 VM:
   ```bash
   TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
   curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/<AWS_ROLE_NAME>
   ```
3. Copy the output fields (`AccessKeyId`, `SecretAccessKey`, `Token`).
4. On your **local terminal**, export these values to configure the environment:
   ```bash
   export AWS_ACCESS_KEY_ID="<AccessKeyId>"
   export AWS_SECRET_ACCESS_KEY="<SecretAccessKey>"
   export AWS_SESSION_TOKEN="<Token>"
   export AWS_DEFAULT_REGION="<AWS_REGION>"
   ```
5. Run the sample script:
   ```bash
   GOOGLE_APPLICATION_CREDENTIALS="/path/to/your/aws-credentials.json" bundle exec ruby samples/regional_access_boundary/workload_identity.rb
   ```

## Running Workload Identity (Azure) Locally

When verifying Azure Workload Identity Federation (`workload_identity.rb`), you can run the test locally on your workstation by fetching the OIDC identity token from the remote Azure VM:

1. SSH into the Azure VM as per the guide:
   ```bash
   ssh -i ~/.ssh/id_rsa_azure byoidtester@<AZURE_VM_IP_ADDRESS>
   ```
2. Retrieve the Azure AD identity token using `curl` inside the Azure VM:
   ```bash
   TOKEN=$(curl "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL_ID>/providers/<PROVIDER_ID>" -H "Metadata:true" -s | jq -r .access_token)
   echo $TOKEN
   ```
3. Copy the printed token value.
4. On your **local terminal**, write it to a local token file:
   ```bash
   echo "<PASTED_TOKEN_VALUE>" > /path/to/azure_subject_token.txt
   ```
5. Create an `azure_credentials.json` configuration file referencing this local token file:
   ```json
   {
     "type": "external_account",
     "audience": "//iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/<POOL_ID>/providers/<PROVIDER_ID>",
     "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
     "token_url": "https://sts.googleapis.com/v1/token",
     "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/<SERVICE_ACCOUNT_EMAIL>:generateAccessToken",
     "credential_source": {
       "file": "/path/to/azure_subject_token.txt"
     }
   }
   ```
6. Run the sample script:
   ```bash
   GOOGLE_APPLICATION_CREDENTIALS="/path/to/your/azure_credentials.json" bundle exec ruby samples/regional_access_boundary/workload_identity.rb
   ```

## Running Workforce Identity (SAML) Locally

When verifying Workforce Identity Federation (`workforce_identity.rb`), you can run the test locally on your workstation by fetching the SAML assertion token from Okta:

1. Create a `login-config.json` file on your workstation:
   ```bash
   export WORKFORCE_POOL_ID="<WORKFORCE_POOL_ID>"
   export PROVIDER_ID="<PROVIDER_ID>"

   gcloud iam workforce-pools create-login-config \
     locations/global/workforcePools/${WORKFORCE_POOL_ID}/providers/${PROVIDER_ID} \
     --output-file=login-config.json
   ```
2. Run the login flow in your terminal:
   ```bash
   gcloud auth login --login-config=login-config.json --no-launch-browser
   ```
3. Open a new Chrome window, open the Network Inspector, and navigate to the URL output by the command above.
4. Log in using your workforce user account (`<WORKFORCE_USER_EMAIL>`).
5. Before clicking "Next" on the "Continue to Google Cloud SDK" screen, look in the Chrome Network tab for the POST request to the `signin-callback` handler (e.g. `https://auth.cloud.google/signin-callback/locations/global/workforcePools/<WORKFORCE_POOL_ID>/providers/<PROVIDER_ID>`).
6. Copy the value of the `SAMLResponse` from the payload of that POST request (excluding the `SAMLResponse=` prefix) and save it raw into a temporary file on your local workstation named `saml_response_encoded.txt`.
7. URL-decode the file contents using a local Ruby command, saving the decoded assertion to a local file:
   ```bash
   ruby -rcgi -e 'puts CGI.unescape(File.read("saml_response_encoded.txt").strip)' > /path/to/saml_assertion.txt
   ```
8. Create a `saml_credentials.json` configuration file referencing this local assertion file:
   ```json
   {
     "type": "external_account",
     "audience": "//iam.googleapis.com/locations/global/workforcePools/<WORKFORCE_POOL_ID>/providers/<PROVIDER_ID>",
     "subject_token_type": "urn:ietf:params:oauth:token-type:saml2",
     "token_url": "https://sts.googleapis.com/v1/token",
     "credential_source": {
       "file": "/path/to/saml_assertion.txt"
     },
     "workforce_pool_user_project": "<WORKFORCE_POOL_USER_PROJECT>"
   }
   ```
9. Run the sample script:
   ```bash
   GOOGLE_APPLICATION_CREDENTIALS="/path/to/your/saml_credentials.json" bundle exec ruby samples/regional_access_boundary/workforce_identity.rb
   ```

## Running Impersonated Service Account (Headful) Locally

### 1. Standard Service Account Impersonation (Test Case 2.2)

To verify standard service account impersonation:

1. Prerequisite: Ensure your corp account has the role `roles/iam.serviceAccountTokenCreator` on `your-impersonated-sa@your-project.iam.gserviceaccount.com`.
2. Generate the impersonated credentials JSON file on your workstation:
   ```bash
   gcloud auth application-default login --impersonate-service-account=your-impersonated-sa@your-project.iam.gserviceaccount.com
   ```
3. Copy the content of the generated ADC file (usually at `~/.config/gcloud/application_default_credentials.json`) and save it to a local file in this workspace, e.g., `impersonated_sa.json`.
4. Run the sample script with `GOOGLE_APPLICATION_CREDENTIALS` pointing to this file:
   ```bash
   GOOGLE_APPLICATION_CREDENTIALS="impersonated_sa.json" bundle exec ruby samples/regional_access_boundary/default_universe.rb
   ```

### 2. Delegated Service Account Impersonation (Test Case 2.2)

To verify delegated service account impersonation:

1. Prerequisite: Ensure your corp account has the role `roles/iam.serviceAccountTokenCreator` on `your-delegated-sa@your-project.iam.gserviceaccount.com` and `your-impersonated-sa@your-project.iam.gserviceaccount.com`.
2. Generate the delegated impersonated credentials JSON file on your workstation:
   ```bash
   gcloud auth application-default login --impersonate-service-account=your-delegated-sa@your-project.iam.gserviceaccount.com,your-impersonated-sa@your-project.iam.gserviceaccount.com
   ```
3. Copy the content of the generated ADC file (usually at `~/.config/gcloud/application_default_credentials.json`) and save it to a local file in this workspace, e.g., `delegated_sa.json`.
4. Run the sample script with `GOOGLE_APPLICATION_CREDENTIALS` pointing to this file:
   ```bash
   GOOGLE_APPLICATION_CREDENTIALS="delegated_sa.json" bundle exec ruby samples/regional_access_boundary/default_universe.rb
   ```

### 3. Workload Identity Federation with Impersonation (Test Case 2.8)

To verify workload identity federation impersonating a service account, you can add `service_account_impersonation_url` to your workload identity JSON configuration file (e.g. AWS or Azure configuration):

1. Edit your `azure_credentials.json` or `aws_credentials.json` file to append the `service_account_impersonation_url` field:
   ```json
   {
     "type": "external_account",
     "audience": "//iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID",
     "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
     "token_url": "https://sts.googleapis.com/v1/token",
     "credential_source": {
       "file": "/path/to/azure_subject_token.txt"
     },
     "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/your-impersonated-sa@your-project.iam.gserviceaccount.com:generateAccessToken"
   }
   ```
2. Run the sample script:
   ```bash
   GOOGLE_APPLICATION_CREDENTIALS="azure_credentials.json" bundle exec ruby samples/regional_access_boundary/workload_identity.rb
   ```



