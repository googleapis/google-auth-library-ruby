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
  
  # Enable WebMock but allow real connections for token fetching
  WebMock.enable!
  WebMock.allow_net_connect!
  
  puts "Loading credentials..."
  begin
    credentials = Google::Auth.get_application_default ["https://www.googleapis.com/auth/cloud-platform"]
  rescue => e
    puts "Failed to load credentials: #{e.message}"
    return
  end

  credentials.logger = Logger.new STDOUT
  credentials.logger.level = Logger::INFO

  puts "Credential Type: #{credentials.class.name}"

  if credentials.is_a? Google::Auth::ServiceAccountCredentials
    email = credentials.instance_variable_get(:@issuer)
    url = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/#{email}/allowedLocations"
    
    # Stub the RAB lookup endpoint to return a 500 error
    stub_request(:get, url)
      .to_return(status: 500, body: "Internal Server Error")
      
    puts "Stubbed #{url} to return 500"
  else
    puts "This sample requires ServiceAccountCredentials to run correctly."
    WebMock.disable!
    return
  end

  bucket_name = "trust_boundary_test_bucket"
  url = "https://storage.googleapis.com/storage/v1/b/#{bucket_name}"

  headers = {}
  
  puts "--- First Call to apply! (should trigger fetch) ---"
  credentials.apply! headers, url: url
  
  puts "\nSleeping for 2 seconds to let background fetch fail..."
  sleep 2

  puts "\n--- Second Call to apply! (should be in cooldown) ---"
  headers = {}
  credentials.apply! headers, url: url
  
  puts "Headers (Second attempt):"
  x_allowed_locations = headers["x-allowed-locations"]
  puts "x-allowed-locations: #{x_allowed_locations || 'NOT PRESENT (Expected after failure)'}"

  if x_allowed_locations
    puts "Failure! RAB header should NOT be present after lookup failure."
  else
    puts "Success! RAB header is not present after lookup failure."
  end

  # Clean up
  WebMock.disable!
end

main if __FILE__ == $0
