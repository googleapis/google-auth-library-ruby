#!/usr/bin/env bash

# Interactive manual test runner for Regional Access Boundary (RAB) in Ruby.
# This script guides you through running each test case and captures the output to a file.

LOG_FILE="ruby_manual_test_results.txt"
rm -f "$LOG_FILE"
touch "$LOG_FILE"

echo "================================================================="
echo "Ruby Regional Access Boundary (RAB) Manual Test Runner"
echo "================================================================="
echo "Results will be saved to: $LOG_FILE"
echo ""

run_test_case() {
  local tc_id="$1"
  local desc="$2"
  local cmd="$3"

  echo "-----------------------------------------------------------------"
  echo "Test Case $tc_id: $desc"
  echo "Command: $cmd"
  echo "-----------------------------------------------------------------"
  
  read -p "Run this test case? [Y/n/skip]: " choice
  case "$choice" in
    [nN]|[sS]*)
      echo "Skipping Test Case $tc_id."
      echo "=== TEST CASE $tc_id: SKIPPED ===" >> "$LOG_FILE"
      echo "" >> "$LOG_FILE"
      return
      ;;
  esac

  echo "Running..."
  echo "=== TEST CASE $tc_id ===" >> "$LOG_FILE"
  echo "Command: $cmd" >> "$LOG_FILE"
  echo "--- OUTPUT ---" >> "$LOG_FILE"
  
  # Run the command and capture stdout/stderr to both terminal and log file
  eval "$cmd" 2>&1 | tee -a "$LOG_FILE"
  
  echo "--------------" >> "$LOG_FILE"
  echo "" >> "$LOG_FILE"
  echo "Test Case $tc_id completed."
  echo ""
}

# -----------------------------------------------------------------
# 1. Setup check
# -----------------------------------------------------------------
if [ -z "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
  echo "Some test cases require a valid Service Account credentials key file."
  echo "Please follow the instructions in the 'SA JWT' tab (tab ID: t.d1buxll8o6l)"
  echo "to download the JSON key for byoid-test@cicpclientproj.iam.gserviceaccount.com."
  echo ""
  read -p "Enter path to SA credentials JSON (or press Enter to skip SA tests): " sa_path
  if [ -n "$sa_path" ]; then
    export GOOGLE_APPLICATION_CREDENTIALS="$sa_path"
  fi
fi

# -----------------------------------------------------------------
# Test Case 1.1: Non-default universe domain
# -----------------------------------------------------------------
run_test_case "1.1" \
  "Non-default universe domain: skip RAB lookup if universe != googleapis.com" \
  "bundle exec ruby samples/regional_access_boundary/non_default_universe.rb"

# -----------------------------------------------------------------
# Test Case 1.2: Default universe domain
# -----------------------------------------------------------------
if [ -n "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
  run_test_case "1.2" \
    "Default universe domain: trigger RAB lookup and cache the result (Instructions: 'SA JWT' tab t.d1buxll8o6l)" \
    "bundle exec ruby samples/regional_access_boundary/default_universe.rb"
else
  echo "Skipping 1.2: SA credentials not set. Follow the 'SA JWT' tab (t.d1buxll8o6l) instructions."
fi

# -----------------------------------------------------------------
# Test Case 1.3: Regional Endpoints
# -----------------------------------------------------------------
if [ -n "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
  run_test_case "1.3" \
    "Regional Endpoints: skip RAB lookup for regional endpoints (Instructions: 'SA JWT' tab t.d1buxll8o6l)" \
    "bundle exec ruby samples/regional_access_boundary/regional_endpoint.rb"
else
  echo "Skipping 1.3: SA credentials not set. Follow the 'SA JWT' tab (t.d1buxll8o6l) instructions."
fi

# -----------------------------------------------------------------
# Test Case 2.1: Service Account Credentials
# -----------------------------------------------------------------
if [ -n "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
  run_test_case "2.1" \
    "Service Account Credentials: check that allowedLocations endpoint uses SA email (Instructions: 'SA JWT' tab t.d1buxll8o6l)" \
    "bundle exec ruby samples/regional_access_boundary/default_universe.rb"
else
  echo "Skipping 2.1: SA credentials not set. Follow the 'SA JWT' tab (t.d1buxll8o6l) instructions."
fi

# -----------------------------------------------------------------
# Test Case 2.2: Impersonated Credentials
# -----------------------------------------------------------------
echo ""
echo "=== Test Case 2.2 ==="
echo "Please follow the instructions in the 'Impersonated SA' tab (tab ID: t.nr3jtpsa0vh2)"
echo "to generate the impersonation credentials file."
echo ""
read -p "Enter path to Impersonated credentials JSON (or press Enter to skip): " imp_path
if [ -n "$imp_path" ]; then
  run_test_case "2.2" \
    "Impersonated Credentials: use target SA email for allowedLocations lookup" \
    "GOOGLE_APPLICATION_CREDENTIALS=\"$imp_path\" bundle exec ruby samples/regional_access_boundary/impersonated.rb"
else
  echo "Skipping 2.2: Impersonated credentials file not provided."
fi

# -----------------------------------------------------------------
# Test Case 2.3 & 2.4: Compute Engine Credentials
# -----------------------------------------------------------------
echo ""
echo "=== Test Case 2.3 & 2.4 (Compute Engine) ==="
echo "To run these cases, you must SSH into the GCE VM 'byoid-test' as described in the"
echo "'Compute Engine' tab (tab ID: t.xq21l8tg84ze) and execute the tests locally within the VM."
echo "This script cannot run them from your local cloudtop session without ambient VM credentials."
echo "  Command to run on VM: bundle exec ruby samples/regional_access_boundary/default_universe.rb"
echo ""

# -----------------------------------------------------------------
# Test Case 2.5: Workforce Identity Federation (OIDC/SAML)
# -----------------------------------------------------------------
echo ""
echo "=== Test Case 2.5 (Workforce Identity Federation) ==="
echo "Please follow the instructions in the 'Workforce Identity' tab (tab ID: t.bfr243arjzef)"
echo "to log in via Okta, capture the token, and build the workforce pool credentials JSON."
echo ""
read -p "Enter path to Workforce Identity config JSON (or press Enter to skip): " wf_path
if [ -n "$wf_path" ]; then
  run_test_case "2.5" \
    "Workforce Identity Federation (Headless): verify RAB lookup for workforce pool" \
    "GOOGLE_APPLICATION_CREDENTIALS=\"$wf_path\" bundle exec ruby samples/regional_access_boundary/workforce_identity.rb"
else
  echo "Skipping 2.5: Workforce credentials file not provided."
fi

# -----------------------------------------------------------------
# Test Case 2.7: Workload Identity Federation (AWS/Azure/etc)
# -----------------------------------------------------------------
echo ""
echo "=== Test Case 2.7 (Workload Identity Federation) ==="
echo "Please refer to the 'Workload Identity' tab (tab ID: t.x7uz9pu4t7) for instructions"
echo "on generating workload credentials (SAML/OIDC/etc). The sample below runs with mocked endpoints."
run_test_case "2.7" \
  "Workload Identity Federation: verify WIF credentials construct lookup URL and cache" \
  "bundle exec ruby samples/regional_access_boundary/workload_identity.rb"

# -----------------------------------------------------------------
# Test Case 2.9: Service Account with self-signed JWT
# -----------------------------------------------------------------
if [ -n "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
  run_test_case "2.9" \
    "Service Account Credentials - using self-signed JWT: skip RAB lookup" \
    "bundle exec ruby samples/regional_access_boundary/self_signed_jwt.rb"
else
  echo "Skipping 2.9: SA credentials not set. Follow the 'SA JWT' tab (t.d1buxll8o6l) instructions."
fi

# -----------------------------------------------------------------
# Test Case 2.10: Unsupported Credentials (User / ID token)
# -----------------------------------------------------------------
run_test_case "2.10" \
  "Unsupported Credentials: skip RAB lookup for user/id token credentials" \
  "bundle exec ruby samples/regional_access_boundary/unsupported.rb"

# -----------------------------------------------------------------
# Test Case 4.1: Lookup Error - Fail Open
# -----------------------------------------------------------------
run_test_case "4.1" \
  "Lookup Error - Fail Open: handle lookup failures without blocking request (Instructions: 'SA JWT' tab t.d1buxll8o6l)" \
  "bundle exec ruby samples/regional_access_boundary/lookup_error.rb"

# -----------------------------------------------------------------
# Test Case 4.2: Retryable Errors & Network Issues
# -----------------------------------------------------------------
run_test_case "4.2" \
  "Retryable Errors: retry lookup on 50x before entering cooldown (Instructions: 'SA JWT' tab t.d1buxll8o6l)" \
  "bundle exec ruby samples/regional_access_boundary/retryable_error.rb"

# -----------------------------------------------------------------
# Test Case 4.3: Malformed Response
# -----------------------------------------------------------------
run_test_case "4.3" \
  "Malformed Response: handle response without encodedLocations safely (Instructions: 'SA JWT' tab t.d1buxll8o6l)" \
  "bundle exec ruby samples/regional_access_boundary/malformed_response.rb"

# -----------------------------------------------------------------
# Test Case 4.4 & 4.5: Cooldown Enforcement & Recovery
# -----------------------------------------------------------------
if [ -n "$GOOGLE_APPLICATION_CREDENTIALS" ]; then
  run_test_case "4.4_4.5" \
    "Cooldown Enforcement & Recovery: enforce cooldown and recover (Instructions: 'SA JWT' tab t.d1buxll8o6l)" \
    "bundle exec ruby samples/regional_access_boundary/cooldown_recovery.rb"
else
  echo "Skipping 4.4 & 4.5: SA credentials not set. Follow the 'SA JWT' tab (t.d1buxll8o6l) instructions."
fi

echo "================================================================="
echo "All manual tests run completed."
echo "Results file saved to: $LOG_FILE"
echo "================================================================="
