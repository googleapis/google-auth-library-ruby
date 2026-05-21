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
  
  puts "Loading credentials..."
  begin
    credentials = Google::Auth.get_application_default ["https://www.googleapis.com/auth/cloud-platform"]
  rescue => e
    puts "Failed to load credentials: #{e.message}"
    return
  end

  # Force self-signed JWT if it is a ServiceAccountCredentials
  if credentials.is_a? Google::Auth::ServiceAccountCredentials
    credentials.instance_variable_set(:@enable_self_signed_jwt, true)
    puts "Forced enable_self_signed_jwt = true"
  else
    puts "This sample requires ServiceAccountCredentials to run correctly."
    return
  end

  credentials.logger = Logger.new STDOUT
  credentials.logger.level = Logger::INFO

  puts "Credential Type: #{credentials.class.name}"

  bucket_name = "trust_boundary_test_bucket"
  url = "https://storage.googleapis.com/storage/v1/b/#{bucket_name}"

  headers = {}
  
  # Set the JWT audience key to avoid returning early in self-signed JWT logic
  headers["jwt_aud_uri"] = "https://storage.googleapis.com/"

  puts "--- Call to apply! with self-signed JWT ---"
  begin
    credentials.apply! headers, url: url
  rescue => e
    puts "Error in apply!: #{e.message}"
    return
  end
  
  puts "Headers:"
  puts "x-allowed-locations: #{headers['x-allowed-locations'] || 'NOT PRESENT (Expected for self-signed JWT)'}"

  if headers["x-allowed-locations"]
    puts "Failure! RAB header should NOT be present for self-signed JWT."
  else
    puts "Success! RAB header is not present for self-signed JWT."
  end
  
  puts "\nFull Headers Hash (Redacted):"
  redacted_headers = headers.dup
  if redacted_headers[:authorization]
    redacted_headers[:authorization] = "Bearer <REDACTED>"
  end
  puts MultiJson.dump(redacted_headers, pretty: true)
end

main if __FILE__ == $0
