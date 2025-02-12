# Copyright 2025 Google LLC
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

module Google
  module Auth
    ##
    # Implementation of Bearer Token authentication scenario.
    #
    # Bearer tokens are strings representing an authorization grant.
    # They can be OAuth2 ("ya.29") tokens, JWTs, IDTokens -- anything
    # that is sent as a `Bearer` in an `Authorization` header.
    #
    # Not all 'authentication' strings can be used with this class,
    # e.g. an API key cannot since API keys are sent in a
    # `x-goog-api-key` header or as a query parameter.
    #
    # This class should be used when the end-user is managing the
    # authentication token separately, e.g. with a separate service.
    # This means that tasks like tracking the lifetime of and
    # refreshing the token are outside the scope of this class.
    #
    # There is no JSON representation for this type of credentials.
    # If the end-user has credentials in JSON format they should typically
    # use the corresponding credentials type, e.g. ServiceAccountCredentials
    # with the service account JSON.
    #
    class BearerTokenCredentials
      include Google::Auth::BaseClient

      # @private Authorization header name
      AUTH_METADATA_KEY = Google::Auth::BaseClient::AUTH_METADATA_KEY

      # @private Allowed token types
      ALLOWED_TOKEN_TYPES = [:access_token, :jwt, :id_token, :bearer_token].freeze

      # @return [String] The token to be sent as a part of Bearer claim
      attr_reader :token
      # The following aliasing is needed for BaseClient since it sends :token_type
      alias access_token token
      alias jwt token
      alias id_token token
      alias bearer_token token

      # @return [Time, nil] The token expiry time provided by the end-user.
      attr_reader :expiry

      # @return [Symbol] The token type. Allowed values are
      #   :access_token, :jwt, :id_token, and :bearer_token.
      attr_reader :token_type

      # @return [String] The universe domain of the universe
      #   this token is for
      attr_accessor :universe_domain

      class << self
        # Create the BearerTokenCredentials.
        #
        # @param [Hash] options The credentials options
        # @option options [String] :token The bearer token to use.
        # @option options [Time, Numeric, nil] :expiry The token expiry time provided by the end-user.
        #   Optional, for the end-user's convenience. Can be a Time object, a number of seconds since epoch.
        #   If the expiry is `nil`, it is treated as "token never expires".
        # @option options [Symbol] :token_type The token type. Allowed values are
        #   :access_token, :jwt, :id_token, and :bearer_token. Defaults to :bearer_token.
        # @option options [String] :universe_domain The universe domain of the universe
        #   this token is for (defaults to googleapis.com)
        # @return [Google::Auth::BearerTokenCredentials]
        def make_creds options = {}
          new options
        end
      end

      # Initialize the BearerTokenCredentials.
      #
      # @param [Hash] options The credentials options
      # @option options [String] :token The bearer token to use.
      # @option options [Time, Numeric, nil] :expiry The token expiry time provided by the end-user.
      #   Optional, for the end-user's convenience. Can be a Time object, a number of seconds since epoch.
      #   If the expiry is `nil`, it is treated as "token never expires".
      # @option options [Symbol] :token_type The token type. Allowed values are
      #   :access_token, :jwt, :id_token, and :bearer_token. Defaults to :bearer_token.
      # @option options [String] :universe_domain The universe domain of the universe
      #   this token is for (defaults to googleapis.com)
      def initialize options = {}
        raise ArgumentError, "Bearer token must be provided" if options[:token].nil? || options[:token].empty?
        @token = options[:token]
        @expiry = if options[:expiry].is_a? Time
                    options[:expiry]
                  elsif options[:expiry].is_a? Numeric
                    Time.at options[:expiry]
                  end

        @token_type = options[:token_type] || :bearer_token
        unless ALLOWED_TOKEN_TYPES.include? @token_type
          raise ArgumentError, "Invalid token type: #{@token_type}. Allowed values are #{ALLOWED_TOKEN_TYPES.inspect}"
        end

        @universe_domain = options[:universe_domain] || "googleapis.com"
      end

      # Determines if the credentials object has expired.
      #
      # @param [Numeric] seconds The optional timeout in seconds.
      # @return [Boolean] True if the token has expired, false otherwise, or
      #   if the expiry was not provided.
      def expires_within? seconds
        return false if @expiry.nil? # Treat nil expiry as "never expires"
        Time.now + seconds >= @expiry
      end

      # Creates a duplicate of these credentials.
      #
      # @param [Hash] options Additional options for configuring the credentials
      # @option options [String] :token The bearer token to use.
      # @option options [Time, Numeric] :expiry The token expiry time. Can be a Time
      #   object or a number of seconds since epoch.
      # @option options [Symbol] :token_type The token type. Allowed values are
      #   :access_token, :jwt, :id_token, and :bearer_token. Defaults to :bearer_token.
      # @option options [String] :universe_domain The universe domain (defaults to googleapis.com)
      # @return [Google::Auth::BearerTokenCredentials]
      def duplicate options = {}
        self.class.new(
          token: options[:token] || @token,
          expiry: options[:expiry] || @expiry,
          token_type: options[:token_type] || @token_type,
          universe_domain: options[:universe_domain] || @universe_domain
        )
      end

      protected

      # We don't need to fetch access tokens for bearer token auth
      def fetch_access_token! _options = {}
        @token
      end

      private

      def token_type_string
        @token_type.to_s.split("_").map(&:capitalize).join(" ") # Nicely format token type for the header
      end
    end
  end
end
