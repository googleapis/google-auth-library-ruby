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

def main
  
  puts "Loading credentials..."
  begin
    credentials = Google::Auth.get_application_default
  rescue => e
    puts "Failed to load credentials: #{e.message}"
    return
  end

  puts "Credential Type: #{credentials.class.name}"
  puts "Universe Domain: #{credentials.universe_domain}"

  # Use a regional endpoint (matches .rep.googleapis.com)
  url = "https://storage.rep.googleapis.com/v1/b/trust_boundary_test_bucket"

  headers = {}
  
  puts "--- Call to apply! with regional endpoint ---"
  begin
    credentials.apply! headers, url: url
  rescue => e
    puts "Error in apply!: #{e.message}"
    return
  end
  
  puts "Headers:"
  puts "x-allowed-locations: #{headers['x-allowed-locations'] || 'NOT PRESENT (Expected for regional endpoint)'}"

  if headers["x-allowed-locations"]
    puts "Failure! RAB header should NOT be present for regional endpoint."
  else
    puts "Success! RAB header is not present for regional endpoint."
  end
end

main if __FILE__ == $0
