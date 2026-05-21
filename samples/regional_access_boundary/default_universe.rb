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
  
  # To run this sample, set the GOOGLE_APPLICATION_CREDENTIALS environment variable
  # to a valid service account JSON key file.
  # ENV["GOOGLE_APPLICATION_CREDENTIALS"] = "path/to/service_account.json"

  puts "Loading credentials..."
  begin
    credentials = Google::Auth.get_application_default ["https://www.googleapis.com/auth/cloud-platform"]
  rescue => e
    puts "Failed to load credentials: #{e.message}"
    puts "Please ensure GOOGLE_APPLICATION_CREDENTIALS is set to a valid JSON file."
    return
  end

  credentials.logger = Logger.new STDOUT

  puts "Credential Type: #{credentials.class.name}"
  puts "Universe Domain: #{credentials.universe_domain}"

  # Replace with name of a bucket that your account has access to
  bucket_name = "trust_boundary_test_bucket"
  url = "https://storage.googleapis.com/storage/v1/b/#{bucket_name}"

  headers = {}
  
  puts "--- First Call to apply! ---"
  begin
    puts "Token Type: #{credentials.token_type}"
    result = credentials.apply! headers, url: url
    puts "apply! return value: Bearer <REDACTED>" if result
    redacted_headers = headers.dup
    if redacted_headers[:authorization]
      redacted_headers[:authorization] = "Bearer <REDACTED>"
    end
    puts "Headers after apply!: #{redacted_headers.inspect}"
  rescue => e
    puts "Error in apply!: #{e.message}"
    return
  end
  
  puts "Headers (First attempt):"
  puts "x-allowed-locations: #{headers['x-allowed-locations'] || 'NOT PRESENT (Expected for cold start in default universe)'}"

  puts "\nSleeping for 5 seconds to let background RAB lookup finish..."
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
  puts "x-allowed-locations: #{x_allowed_locations || 'STILL NOT PRESENT (Lookup might have failed or still in progress)'}"

  if x_allowed_locations
    puts "Success! RAB header is present for the default universe."
  else
    puts "Failure! RAB header should be present for the default universe if configured."
  end

  puts "\nFull Headers Hash (Redacted):"
  redacted_headers = headers.dup
  if redacted_headers[:authorization]
    redacted_headers[:authorization] = "Bearer <REDACTED>"
  end
  puts MultiJson.dump(redacted_headers, pretty: true)
end

main if __FILE__ == $0
