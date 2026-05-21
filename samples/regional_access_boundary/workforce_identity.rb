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
require "webmock"
require "logger"

include WebMock::API

def main
  
  # Enable WebMock but allow real connections for other potential calls
  WebMock.enable!
  WebMock.allow_net_connect!
  
  config_path = File.expand_path("workforce_identity_config.json", __dir__)
  ENV["GOOGLE_APPLICATION_CREDENTIALS"] = config_path
  
  puts "Loading credentials from #{config_path}..."
  begin
    credentials = Google::Auth.get_application_default ["https://www.googleapis.com/auth/cloud-platform"]
  rescue => e
    puts "Failed to load credentials: #{e.message}"
    WebMock.disable!
    return
  end

  credentials.logger = Logger.new STDOUT
  credentials.logger.level = Logger::INFO

  puts "Credential Type: #{credentials.class.name}"
  puts "Universe Domain: #{credentials.universe_domain}"

  # 1. Stub the external token source
  stub_request(:get, "http://dummyurl.com/token")
    .to_return(status: 200, body: MultiJson.dump({ "access_token" => "external_subject_token" }))
    
  # 2. Stub the STS token exchange
  stub_request(:post, "https://sts.googleapis.com/v1/token")
    .to_return(status: 200, body: MultiJson.dump({
      "access_token" => "sts_access_token",
      "issued_token_type" => "urn:ietf:params:oauth:token-type:access_token",
      "token_type" => "Bearer",
      "expires_in" => 3600
    }))

  # 3. Stub the RAB lookup endpoint for Workforce Identity
  url = "https://iamcredentials.googleapis.com/v1/locations/global/workforcePools/POOL_ID/allowedLocations"
  stub_request(:get, url)
    .to_return(status: 200, body: MultiJson.dump({ "encodedLocations" => "0x7ffffffffffffffe" }))
    
  puts "Stubbed external token source, STS exchange, and RAB lookup."

  bucket_name = "trust_boundary_test_bucket"
  url = "https://storage.googleapis.com/storage/v1/b/#{bucket_name}"

  headers = {}
  
  puts "--- First Call to apply! (should trigger fetch) ---"
  begin
    credentials.apply! headers, url: url
  rescue => e
    puts "Error in apply!: #{e.message}"
    WebMock.disable!
    return
  end
  
  puts "Headers (First attempt):"
  puts "x-allowed-locations: #{headers['x-allowed-locations'] || 'NOT PRESENT (Expected for cold start)'}"

  puts "\nSleeping for 5 seconds to let background fetch complete..."
  sleep 5

  headers = {}
  puts "--- Second Call to apply! ---"
  begin
    credentials.apply! headers, url: url
  rescue => e
    puts "Error in apply!: #{e.message}"
    WebMock.disable!
    return
  end
  
  puts "Headers (Second attempt):"
  x_allowed_locations = headers["x-allowed-locations"]
  puts "x-allowed-locations: #{x_allowed_locations || 'STILL NOT PRESENT'}"

  if x_allowed_locations == "0x7ffffffffffffffe"
    puts "Success! RAB header is present for workforce identity."
  else
    puts "Failure! RAB header should be present for workforce identity."
  end

  puts "\nFull Headers Hash (Redacted):"
  redacted_headers = headers.dup
  if redacted_headers[:authorization]
    redacted_headers[:authorization] = "Bearer <REDACTED>"
  end
  puts MultiJson.dump(redacted_headers, pretty: true)

  # Clean up
  WebMock.disable!
end

main if __FILE__ == $0
