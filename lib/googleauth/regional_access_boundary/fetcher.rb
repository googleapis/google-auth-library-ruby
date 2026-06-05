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
        def initialize client, url, token
          @client = client
          @url = url
          @token = token
        end

        # Fetches the data, applying retry logic for transient errors.
        # @raise [Google::Auth::AuthorizationError] if the fetch fails.
        def fetch
          start_time = Time.now
          attempt = 0

          # For retryable errors (500, 502, 503, 504), perform retry with
          # exponential backoff for up to one minute.
          loop do
            attempt += 1
            begin
              response = perform_request
              return handle_response response
            rescue StandardError => e
              handle_error e, attempt, start_time
            end
          end
        end

        private

        def perform_request
          @client.get @url do |req|
            # token_type is private in some credentials, so we use send to access it.
            token_name = @token.send :token_type
            token_val = @token.send token_name
            req.headers["Authorization"] = "Bearer #{token_val}"
          end
        end

        def handle_response response
          if response.status == 200
            body = MultiJson.load response.body
            if body["encodedLocations"].nil? || body["encodedLocations"].empty?
              raise Google::Auth::AuthorizationError, "Invalid response: encodedLocations is empty"
            end
            # Use fully qualified name to avoid resolution issues
            Google::Auth::RegionalAccessBoundary::RegionalAccessBoundaryData.new body["encodedLocations"]
          elsif [500, 502, 503, 504].include? response.status
            # Retryable errors
            raise "Retryable status: #{response.status}"
          else
            raise Google::Auth::AuthorizationError, "Lookup failed with status #{response.status}"
          end
        end

        def handle_error error, attempt, start_time
          # Check if we should retry
          is_retryable = error.message.start_with?("Retryable status:") || error.is_a?(Faraday::Error)

          raise Google::Auth::AuthorizationError, "RAB lookup failed: #{error.message}" unless is_retryable
          if Time.now - start_time > 60
            raise Google::Auth::AuthorizationError, "Retries exhausted for RAB lookup: #{error.message}"
          end

          # Exponential backoff: 1s, 2s, 4s... up to 60s max
          sleep_time = [2**(attempt - 1), 60].min
          sleep sleep_time
        end
      end
    end
  end
end
