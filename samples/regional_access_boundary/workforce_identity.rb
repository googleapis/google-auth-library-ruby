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
require "json"
require "logger"

def main
  puts "Loading credentials..."
  begin
    # This will load credentials from GOOGLE_APPLICATION_CREDENTIALS
    credentials = Google::Auth.get_application_default ["https://www.googleapis.com/auth/cloud-platform"]
  rescue StandardError => e
    puts "Failed to load credentials: #{e.message}"
    return
  end

  credentials.logger = Logger.new $stdout
  credentials.logger.level = Logger::INFO

  puts "Credential Type: #{credentials.class.name}"
  puts "Universe Domain: #{credentials.universe_domain}"

  bucket_name = "trust_boundary_test_bucket"
  url = "https://storage.googleapis.com/storage/v1/b/#{bucket_name}"

  headers = {}

  puts "--- First Call to apply! (should trigger fetch) ---"
  begin
    credentials.apply! headers, url: url
  rescue StandardError => e
    puts "Error in apply!: #{e.message}"
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
  rescue StandardError => e
    puts "Error in apply!: #{e.message}"
    return
  end

  puts "Headers (Second attempt):"
  x_allowed_locations = headers["x-allowed-locations"]
  puts "x-allowed-locations: #{x_allowed_locations || 'STILL NOT PRESENT'}"

  if x_allowed_locations && x_allowed_locations != 'STILL NOT PRESENT'
    puts "Success! RAB header is present for workforce identity: #{x_allowed_locations}"
  else
    puts "Failure! RAB header should be present for workforce identity."
  end

  puts "\nFull Headers Hash (Redacted):"
  redacted_headers = headers.dup
  if redacted_headers[:authorization]
    redacted_headers[:authorization] = "Bearer <REDACTED>"
  end
  puts JSON.pretty_generate(redacted_headers)
end

main if __FILE__ == $PROGRAM_NAME
