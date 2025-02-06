# Copyright 2024 Google LLC
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

require "googleauth/base_client"
require "googleauth/credentials_loader"

module Google
  module Auth
    ##
    # Implementation of Google API Key authentication.
    #
    # API Keys are text strings. They don't have an associated JSON file.
    #
    # The end-user is managing their API Keys directly, not via
    # an authentication library.
    #
    # API Keys provide project information for an API request.
    # API Keys don't reference an IAM principal, they do not expire,
    # and cannot be refreshed.
    #
    class APIKeyCredentials
      include Google::Auth::BaseClient

      # Authorization header key
      API_KEY_HEADER = "x-goog-api-key".freeze

      # Environment variable containing API key
      API_KEY_VAR = "GOOGLE_API_KEY".freeze

      # @private The API key
      attr_reader :api_key

      # @private The universe domain
      attr_accessor :universe_domain

      # Initialize the APIKeyCredentials.
      #
      # @param [Hash] options The credentials options
      # @option options [String] :api_key
      #   The API key to use for authentication
      # @option options [String] :universe_domain
      #   The universe domain (defaults to googleapis.com)
      def initialize options = {}
        raise ArgumentError, "API key must be provided" if options[:api_key].nil?
        @api_key = options[:api_key]
        @universe_domain = options[:universe_domain] || "googleapis.com"
      end

      # Determines if the credentials object has expired.
      # Since API keys don't expire, this always returns false.
      #
      # @param [Fixnum] _seconds
      #  The optional timeout in seconds since the last refresh
      # @return [Boolean]
      #  True if the token has expired, false otherwise.
      def expires_within? _seconds
        false
      end

      # Creates a duplicate of these credentials.
      #
      # @param [Hash] options Additional options for configuring the credentials
      # @return [Google::Auth::APIKeyCredentials]
      def duplicate options = {}
        self.class.new(
          api_key: options[:api_key] || @api_key,
          universe_domain: options[:universe_domain] || @universe_domain
        )
      end

      protected

      # The token type should be :api_key
      def token_type
        :api_key
      end

      # We don't need to fetch access tokens for API key auth
      def fetch_access_token! _options = {}
        nil
      end

      class << self
        # Creates an APIKeyCredentials from the environment.
        # Checks the ENV['GOOGLE_API_KEY'] variable.
        #
        # @param [String] scope
        #  The scope to use for OAuth. Not used by API key auth.
        # @param [Hash] options
        #  The options to pass to the credentials instance
        #
        # @return [Google::Auth::APIKeyCredentials, nil]
        #  Credentials if the API key environment variable is present, nil otherwise
        def from_env _scope = nil, options = {}
          api_key = ENV[API_KEY_VAR]
          return nil if api_key.nil? || api_key.empty?
          new options.merge(api_key: api_key)
        end
      end

      def apply! a_hash, _opts = {}
        a_hash[API_KEY_HEADER] = @api_key
        logger&.debug do
          hash = Digest::SHA256.hexdigest @api_key
          Google::Logging::Message.from message: "Sending API key auth token. (sha256:#{hash})"
        end
        a_hash
      end
    end
  end
end
