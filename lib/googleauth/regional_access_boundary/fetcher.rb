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
require "json"
require "googleauth/errors"

module Google
  module Auth
    module RegionalAccessBoundary
      # TransientLookupError is raised when a transient error occurs during lookup,
      # signaling that the request should be retried.
      #
      # @private
      class TransientLookupError < StandardError; end

      # Fetcher handles retrieving Regional Access Boundary data from the API.
      #
      # @private
      class Fetcher
        # @param client [Faraday::Connection] the HTTP client used to fetch allowedLocations.
        # @param url [String] the allowedLocations endpoint URL.
        # @param token [Object] the credentials token instance.
        def initialize client, url, token
          @client = client
          @url = url
          @token = token
        end

        # Fetches the data, applying retry logic for transient errors.
        #
        # @raise [Google::Auth::AuthorizationError] if the fetch fails.
        # @return [Google::Auth::RegionalAccessBoundary::RegionalAccessBoundaryData] the fetched data.
        def fetch
          start_time = Time.now
          attempt = 0

          # Perform retry with exponential backoff for up to one minute.
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

        # @return [Faraday::Response] the HTTP response.
        def perform_request
          @client.get @url do |req|
            # token_type is private in some credentials, so we use send to access it.
            token_name = @token.send :token_type
            token_val = @token.send token_name
            req.headers["Authorization"] = "Bearer #{token_val}"
          end
        end

        # @param response [Faraday::Response] the HTTP response.
        # @raise [Google::Auth::AuthorizationError] if the response contains invalid data.
        # @raise [TransientLookupError] if response is retryable (5xx).
        # @return [Google::Auth::RegionalAccessBoundary::RegionalAccessBoundaryData]
        def handle_response response
          if response.status == 200
            body = ::JSON.parse response.body
            if body["encodedLocations"].nil? || body["encodedLocations"].empty?
              raise Google::Auth::AuthorizationError, "Invalid response: encodedLocations is empty"
            end
            # Use fully qualified name to avoid resolution issues
            Google::Auth::RegionalAccessBoundary::RegionalAccessBoundaryData.new body["encodedLocations"]
          elsif [500, 502, 503, 504].include? response.status
            # Retryable errors
            raise TransientLookupError, "Status: #{response.status}"
          else
            raise Google::Auth::AuthorizationError, "Lookup failed with status #{response.status}"
          end
        end

        # @param error [StandardError] the error to evaluate.
        # @param attempt [Integer] the current retry attempt count.
        # @param start_time [Time] the timestamp when the first lookup attempt started.
        # @raise [Google::Auth::AuthorizationError] if the error is not retryable or retries are exhausted.
        # @return [void]
        def handle_error error, attempt, start_time
          # Check if we should retry
          is_retryable = error.is_a?(TransientLookupError) || error.is_a?(Faraday::Error)

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
