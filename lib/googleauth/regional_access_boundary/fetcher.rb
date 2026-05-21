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

require "faraday"
require "multi_json"
require "googleauth/errors"

module Google
  module Auth
    module RegionalAccessBoundary
      # Fetcher handles retrieving Regional Access Boundary data from the API.
      class Fetcher
        def initialize client, url, token, logger = nil
          @client = client
          @url = url
          @token = token
          @logger = logger
        end

        # Fetches the data, applying retry logic for transient errors.
        # Raises Google::Auth::AuthorizationError on failure.
        def fetch
          start_time = Time.now
          attempt = 0
          
          # For retryable errors (500, 502, 503, 504), perform an asynchronous retry with exponential backoff for up to one minute.
          loop do
            attempt += 1
            begin
              response = @client.get(@url) do |req|
                # token_type is private in some credentials, so we use send to access it.
                token_name = @token.send(:token_type)
                token_val = @token.send(token_name)
                req.headers["Authorization"] = "Bearer #{token_val}"
              end
              
              if response.status == 200
                body = MultiJson.load response.body
                if body["encodedLocations"].nil? || body["encodedLocations"].empty?
                  raise Google::Auth::AuthorizationError, "Invalid response: encodedLocations is empty"
                end
                # Use fully qualified name to avoid resolution issues
                return Google::Auth::RegionalAccessBoundary::RegionalAccessBoundaryData.new body["encodedLocations"]
              elsif [500, 502, 503, 504].include? response.status
                # Retryable errors
                raise "Retryable status: #{response.status}"
              else
                # Non-retryable errors
                raise Google::Auth::AuthorizationError, "Lookup failed with status #{response.status}: #{response.body}"
              end
            rescue => e
              # Check if we should retry
              is_retryable = e.message.start_with?("Retryable status:") || e.is_a?(Faraday::Error)
              
              if is_retryable
                if Time.now - start_time > 60
                  raise Google::Auth::AuthorizationError, "Retries exhausted for RAB lookup: #{e.message}"
                end
                
                # Exponential backoff: 1s, 2s, 4s... up to 60s max
                sleep_time = [2**(attempt - 1), 60].min
                sleep sleep_time
                retry
              else
                raise Google::Auth::AuthorizationError, "RAB lookup failed: #{e.message}"
              end
            end
          end
        end
      end
    end
  end
end
