# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "googleauth"
require "faraday"
require "multi_json"
require "logger"

def main
  
  puts "Loading base credentials..."
  begin
    base_credentials = Google::Auth.get_application_default ["https://www.googleapis.com/auth/cloud-platform"]
  rescue => e
    puts "Failed to load base credentials: #{e.message}"
    return
  end

  # Use the service account email from your previous output as the target
  target_email = "chrisdsmith-tests@helical-zone-771.iam.gserviceaccount.com"
  impersonation_url = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/#{target_email}:generateAccessToken"

  puts "Creating Impersonated Credentials..."
  credentials = Google::Auth::ImpersonatedServiceAccountCredentials.new(
    base_credentials: base_credentials,
    impersonation_url: impersonation_url,
    scope: ["https://www.googleapis.com/auth/cloud-platform"]
  )

  base_credentials.logger = Logger.new STDOUT
  base_credentials.logger.level = Logger::INFO

  puts "Credential Type: #{credentials.class.name}"
  puts "Target Email: #{target_email}"

  bucket_name = "trust_boundary_test_bucket"
  url = "https://storage.googleapis.com/storage/v1/b/#{bucket_name}"

  headers = {}
  
  puts "--- First Call to apply! ---"
  begin
    credentials.apply! headers, url: url
  rescue => e
    puts "Error in apply!: #{e.message}"
    return
  end
  
  puts "Headers:"
  puts "x-allowed-locations: #{headers['x-allowed-locations'] || 'NOT PRESENT (Expected for cold start)'}"

  puts "\nSleeping for 5 seconds to let background fetch complete..."
  sleep 5

  headers = {}
  puts "--- Second Call to apply! ---"
  begin
    credentials.apply! headers, url: url
  rescue => e
    puts "Error in apply!: #{e.message}"
    return
  end
  
  puts "Headers (Second attempt):"
  x_allowed_locations = headers["x-allowed-locations"]
  puts "x-allowed-locations: #{x_allowed_locations || 'STILL NOT PRESENT'}"

  if x_allowed_locations
    puts "Success! RAB header is present for impersonated credentials."
  else
    puts "Failure! RAB header should be present if allowlisted."
  end

  puts "\nFull Headers Hash (Redacted):"
  redacted_headers = headers.dup
  if redacted_headers[:authorization]
    redacted_headers[:authorization] = "Bearer <REDACTED>"
  end
  puts MultiJson.dump(redacted_headers, pretty: true)
end

main if __FILE__ == $0
