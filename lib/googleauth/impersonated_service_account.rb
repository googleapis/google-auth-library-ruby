# Copyright 2024 Google, Inc.
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

require "googleauth/signet"
require "googleauth/base_client"
require "googleauth/helpers/connection"

module Google
  module Auth
    # Authenticates requests using impersonation from base credentials.
    # This is a two-step process: first authentication claim from the base credentials is created
    # and then that claim is exchanged for a short-lived token at an IAMCredentials endpoint.
    # The short-lived token and its expiration time are cached.
    class ImpersonatedServiceAccountCredentials
      # @private
      ERROR_SUFFIX = <<~ERROR.freeze
        trying to get security access token
        from IAM Credentials endpoint using the credentials provided.
      ERROR

      # @private
      IAM_SCOPE = ["https://www.googleapis.com/auth/iam".freeze].freeze

      include Google::Auth::BaseClient
      include Helpers::Connection

      # @!attribute [r] base_credentials
      #   @return [Object] The original authenticated credentials used to fetch short-lived impersonation access tokens.
      attr_reader :base_credentials

      # @!attribute [r] source_credentials
      #   @return [Object] The modified version of base credentials, tailored for impersonation purposes with necessary scope adjustments.
      attr_reader :source_credentials

      # @!attribute [r] impersonation_url
      #   @return [String] The URL endpoint used to generate an impersonation token. This URL should follow a specific format
      #     to specify the impersonated service account.
      attr_reader :impersonation_url

      # @!attribute [r] scope
      #   @return [Array<String>, String] The scope(s) required for the impersonated access token, indicating the permissions needed for the short-lived token.
      attr_reader :scope

      # @!attribute [r] access_token
      #   @return [String, nil] The short-lived impersonation access token, retrieved and cached after making the impersonation request.
      attr_reader :access_token

      # @!attribute [r] expires_at
      #   @return [Time, nil] The expiration time of the current access token, used to determine if the token is still valid.
      attr_reader :expires_at

      # Create a ImpersonatedServiceAccountCredentials
      # When you use service account impersonation, you start with an authenticated principal
      # (e.g. your user account or a service account)
      # and request short-lived credentials for a service account
      # that has the authorization that your use case requires.
      #
      # @param base_credentials [Object] the authenticated principal that will be used
      #   to fetch short-lived impersionation access token
      # @param impersonation_url [String] the URL to use to impersonate the service account.
      #   This URL should be in the format:
      #   `https://iamcredentials.{universe_domain}/v1/projects/-/serviceAccounts/{source_sa_email}:generateAccessToken`
      #   where:
      #     * `{universe_domain}` is the domain of the IAMCredentials API endpoint (e.g. 'googleapis.com')
      #     * `{source_sa_email}` is the email address of the service account to impersonate
      # @param scope [Array, String] the scope(s) to access.
      #   Note that these are NOT the scopes that the authenticated principal should have, but
      #   the scopes that the short-lived impersonation access token should have.
      #
      # @return [Google::Auth::ImpersonatedServiceAccountCredentials]
      def self.make_creds options = {}
        new options
      end

      # Initializes a new instance of ImpersonatedServiceAccountCredentials.
      #
      # @param options [Hash] A hash of options to configure the credentials.
      # @option options [Object] :base_credentials (required) The authenticated principal that will be used
      #   to fetch the short-lived impersonation access token.
      # @option options [String] :impersonation_url (required) The URL to impersonate the service account.
      #   This URL should follow the format:
      #   `https://iamcredentials.{universe_domain}/v1/projects/-/serviceAccounts/{source_sa_email}:generateAccessToken`,
      #   where:
      #     - `{universe_domain}` is the domain of the IAMCredentials API endpoint (e.g., `googleapis.com`).
      #     - `{source_sa_email}` is the email address of the service account to impersonate.
      # @option options [Array<String>, String] :scope (required) The scope(s) for the short-lived impersonation token,
      #   defining the permissions required for the token.
      #
      # @raise [ArgumentError] If any of the required options are missing.
      #
      # @return [Google::Auth::ImpersonatedServiceAccountCredentials]
      def initialize options = {}
        @base_credentials, @impersonation_url, @scope =
          options.values_at :base_credentials,
                            :impersonation_url,
                            :scope

        # Fail-fast checks for required parameters
        raise ArgumentError, "Missing required option: :base_credentials" if @base_credentials.nil?
        raise ArgumentError, "Missing required option: :impersonation_url" if @impersonation_url.nil?
        raise ArgumentError, "Missing required option: :scope" if @scope.nil?

        # Some credentials (all Signet-based ones and this one) include scope and a bunch of transient state
        # (e.g. refresh status) as part of themselves
        # so a copy needs to be created with the scope overriden and transient state dropped.
        #
        # If a credentials does not support `duplicate` we'll try to use it as is assuming it has a broad enough scope.
        # This might result in an "access denied" error downstream when the token from that credentials is being used for
        # the token exchange.
        @source_credentials = if @base_credentials.respond_to? :duplicate
                                @base_credentials.duplicate({
                                                              scope: IAM_SCOPE
                                                            })
                              else
                                @base_credentials
                              end
      end

      # Determines whether the current access token expires within the specified number of seconds.
      #
      # @param seconds [Integer] The number of seconds to check against the token's expiration time.
      #
      # @return [Boolean] Whether the access token expires within the given time frame
      def expires_within? seconds
        # This method is needed for BaseClient
        @expires_at && @expires_at - Time.now.utc < seconds
      end

      # The universe domain of the impersonated credentials.
      # Effectively this retrieves the universe domain of the source credentials.
      #
      # @return [String] The universe domain of the credentials.
      def universe_domain
        @source_credentials.universe_domain
      end

      # Returns a clone of a_hash updated with the authoriation header
      # Updates the given hash with an authorization header containing the impersonation access token.
      #
      # This method generates a short-lived impersonation access token (if not already cached or valid)
      # and adds it to the provided hash as a `Bearer` token in the authorization metadata key.
      #
      # @param a_hash [Hash] The hash to be updated with the authorization header.
      # @param _opts [Hash] (optional) Additional options for token application (currently unused).
      # @return [Hash] The updated hash containing the authorization header.
      # @raise [Signet::AuthorizationError] If token generation fails
      # def apply! a_hash, _opts = {}
      #   if @access_token && !expires_within?(60)
      #     # Use the cached token if it's still valid
      #     token = @access_token
      #   else
      #     # Generate a new token if the current one is expired or not present
      #     token = fetch_access_token!
      #   end

      #   a_hash[AUTH_METADATA_KEY] = "Bearer #{token}"
      #   a_hash
      # end

      # Creates a duplicate of these credentials without transient token state
      #
      # @param options [Hash] Overrides for the credentials parameters.
      #   The following keys are recognized
      #   * `base_credentials` the base credentials used to initialize the impersonation
      #   * `source_credentials` the authenticated credentials which usually would be
      #     base credentias with scope overridden to IAM_SCOPE
      #   * `impersonation_url` the URL to use to make an impersonation token exchange
      #   * `scope` the scope(s) to access
      def duplicate options = {}
        options = deep_hash_normalize options

        options = {
          base_credentials: @base_credentials,
          source_credentials: @source_credentials,
          impersonation_url: @impersonation_url,
          scope: @scope
        }.merge(options)

        new_client = self.class.new options
        new_client.update! options
      end

      # Destructively updates these credentials
      #
      # @param options [Hash] Overrides for the credentials parameters.
      #   The following keys are recognized
      #   * `base_credentials` the base credentials used to initialize the impersonation
      #   * `source_credentials` the authenticated credentials which usually would be
      #     base credentias with scope overridden to IAM_SCOPE
      #   * `impersonation_url` the URL to use to make an impersonation token exchange
      #   * `scope` the scope(s) to access
      def update! options = {}
        # Normalize all keys to symbols to allow indifferent access.
        options = deep_hash_normalize options

        @base_credentials = options[:base_credentials] if options.key? :base_credentials
        @source_credentials = options[:source_credentials] if options.key? :source_credentials
        @impersonation_url = options[:impersonation_url] if options.key? :impersonation_url
        @scope = options[:scope] if options.key? :scope

        self
      end

      private

      # Generates a new impersonation access token by exchanging the source credentials' token
      # at the impersonation URL.
      #
      # This method first fetches an access token from the source credentials and then exchanges it
      # for an impersonation token using the specified impersonation URL. The generated token and
      # its expiration time are cached for subsequent use.
      #
      # @param _options [Hash] (optional) Additional options for token retrieval (currently unused).
      #
      # @raise [Signet::UnexpectedStatusError] If the response status is 403 or 500.
      # @raise [Signet::AuthorizationError] For other unexpected response statuses.
      #
      # @return [String] The newly generated impersonation access token.
      def fetch_access_token! _options = {}
        auth_header = {}
        auth_header = @source_credentials.apply! auth_header

        resp = connection.post @impersonation_url do |req|
          req.headers.merge! auth_header
          req.headers["Content-Type"] = "application/json"
          req.body = MultiJson.dump({ scope: @scope })
        end

        case resp.status
        when 200
          response = MultiJson.load resp.body
          self.expires_at = response["expireTime"]
          self.access_token = response["accessToken"]
          access_token
        when 403, 500
          msg = "Unexpected error code #{resp.status} #{ERROR_SUFFIX}"
          raise Signet::UnexpectedStatusError, msg
        else
          msg = "Unexpected error code #{resp.status} #{ERROR_SUFFIX}"
          raise Signet::AuthorizationError, msg
        end
      end

      # Setter for the expires_at value that makes sure it is converted
      def expires_at= new_expires_at
        @expires_at = normalize_timestamp new_expires_at
      end

      attr_writer :access_token

      def token_type
        # This method is needed for BaseClient
        :access_token
      end

      def normalize_timestamp time
        case time
        when NilClass
          nil
        when Time
          time
        when String
          Time.parse time
        else
          raise "Invalid time value #{time}"
        end
      end

      # Convert all keys in this hash (nested) to symbols for uniform retrieval
      def recursive_hash_normalize_keys val
        if val.is_a? Hash
          deep_hash_normalize val
        else
          val
        end
      end

      def deep_hash_normalize old_hash
        sym_hash = {}
        old_hash&.each { |k, v| sym_hash[k.to_sym] = recursive_hash_normalize_keys v }
        sym_hash
      end
    end
  end
end
