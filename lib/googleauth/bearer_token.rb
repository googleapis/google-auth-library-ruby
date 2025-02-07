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

module Google
  module Auth
    ##
    # Implementation of Bearer Token authentication.
    #
    # Bearer tokens are strings representing an authorization grant.  They
    # are typically used with OAuth 2.0.
    #
    class BearerTokenCredentials
      include Google::Auth::BaseClient

      # Authorization header key
      BEARER_TOKEN_HEADER = "Authorization".freeze

      # Allowed token types
      ALLOWED_TOKEN_TYPES = [:access_token, :jwt, :id_token, :bearer_token].freeze

      # @private The bearer token
      attr_reader :bearer_token

      # @private The token expiry time (Time object or nil)
      attr_reader :expiry

       # @private The token type
      attr_reader :token_type

      # @private The universe domain
      attr_accessor :universe_domain

      # Initialize the BearerTokenCredentials.
      #
      # @param [Hash] options The credentials options
      # @option options [String] :bearer_token The bearer token to use.
      # @option options [Time, Numeric] :expiry The token expiry time. Can be a Time
      #   object or a number of seconds since epoch.
      # @option options [Symbol] :token_type The token type. Allowed values are
      #   :access_token, :jwt, :id_token, and :bearer_token. Defaults to :bearer_token.
      # @option options [String] :universe_domain The universe domain (defaults to googleapis.com)
      def initialize options = {}
        raise ArgumentError, "Bearer token must be provided" if options[:bearer_token].nil? || options[:bearer_token].empty?
        @bearer_token = options[:bearer_token]
        @expiry = if options[:expiry].is_a?(Time)
                    options[:expiry]
                  elsif options[:expiry].is_a?(Numeric)
                    Time.at(options[:expiry])
                  end

        @token_type = options[:token_type] || :bearer_token
        unless ALLOWED_TOKEN_TYPES.include?(@token_type)
          raise ArgumentError, "Invalid token type: #{@token_type}. Allowed values are #{ALLOWED_TOKEN_TYPES.inspect}"
        end

        @universe_domain = options[:universe_domain] || "googleapis.com"
      end

      # Determines if the credentials object has expired.
      #
      # @param [Numeric] seconds The optional timeout in seconds.
      # @return [Boolean] True if the token has expired, false otherwise.
      def expires_within? seconds = 0
        return false if @expiry.nil?
        Time.now + seconds >= @expiry
      end

      # Creates a duplicate of these credentials.
      #
      # @param [Hash] options Additional options for configuring the credentials
      # @return [Google::Auth::BearerTokenCredentials]
      def duplicate options = {}
        self.class.new(
          bearer_token: options[:bearer_token] || @bearer_token,
          expiry: options[:expiry] || @expiry,
          universe_domain: options[:universe_domain] || @universe_domain
        )
      end

      protected

      # The token type should be :bearer
      def token_type
        :bearer
      end

      # We don't need to fetch access tokens for bearer token auth
      def fetch_access_token! _options = {}
        nil
      end

      class << self
        # Create the BearerTokenCredentials.
        #
        # @param [Hash] options The credentials options
        # @option options [String] :bearer_token The bearer token to use.
        # @option options [Time, Numeric] :expiry The token expiry time. Can be a Time
        #   object or a number of seconds since epoch.
        # @option options [String] :universe_domain The universe domain (defaults to googleapis.com)
        # @return [Google::Auth::BearerTokenCredentials]
        def make_creds options = {}
          new options
        end
      end

      def apply! a_hash, _opts = {}
        a_hash[BEARER_TOKEN_HEADER] = "#{token_type_string} #{@bearer_token}" # Use token_type_string method
        logger&.debug do
          Google::Logging::Message.from message: "Sending #{token_type_string} auth token. (truncated)" # Consider logging hash instead
        end
        a_hash
      end

      private

      def token_type_string
        @token_type.to_s.split('_').map(&:capitalize).join(' ') #Nicely format token type for the header
      end
    end
  end
end