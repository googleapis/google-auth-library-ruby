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
      ERROR_SUFFIX = <<~ERROR.freeze
        trying to get security access token
        from IAM Credentials endpoint using the credentials provided.
      ERROR

      IAM_SCOPE = ["https://www.googleapis.com/auth/iam".freeze].freeze

      include Google::Auth::BaseClient
      include Helpers::Connection
      
      attr_reader :base_credentials, :source_credentials, :impersonation_url, :scope
      attr_reader :access_token, :expires_at
      
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
      #   https://iamcredentials.{universe_domain}/v1/projects/-/serviceAccounts/{source_sa_email}:generateAccessToken
      #   where:
      #     * {universe_domain} is the domain of the IAMCredentials API endpoint (e.g. 'googleapis.com')
      #     * {source_sa_email} is the email address of the service account to impersonate
      # @param scope [Array, String] the scope(s) to access.
      #   Note that these are NOT the scopes that the authenticated principal should have, but
      #   the scopes that the short-lived impersonation access token should have.
      def self.make_creds options = {}
        new(options)
      end

      def initialize options = {}
        @base_credentials, @impersonation_url, @scope  =
          options.values_at :base_credentials, 
                            :impersonation_url,
                            :scope

        # Some credentials (all Signet-based ones and this one) include scope and a bunch of transient state (e.g. refresh status) as part of themselves
        # so a copy needs to be created with the scope overriden and transient state dropped
        @source_credentials = if @base_credentials.respond_to? :duplicate 
          @base_credentials.duplicate({
            scope: IAM_SCOPE
          })
        else
          @base_credentials
        end
      end

      # Whether the current access token expires before a given
      # amount of seconds is elapsed
      def expires_within? seconds
        # This method is needed for BaseClient
        @expires_at && @expires_at - Time.now.utc < seconds
      end

      def universe_domain
        @source_credentials.universe_domain
      end

      # Calls the source credentials to fetch an access token first,
      # then exchanges that access token for an impersonation token
      # at the @impersonation_url
      def make_token!
        auth_header = {}
        auth_header = @source_credentials.apply! auth_header

        resp = connection.post @impersonation_url do |req|
          req.headers.merge! auth_header
          req.headers["Content-Type"] = "application/json"
          req.body = MultiJson.dump({ scope: @scope })
        end

        case resp.status
        when 200
          response = MultiJson.load(resp.body)
          self.expires_at = response["expireTime"]
          self.access_token = response["accessToken"]
          self.access_token
        when 403, 500
          msg = "Unexpected error code #{resp.status} #{ERROR_SUFFIX}"
          raise Signet::UnexpectedStatusError, msg
        else
          msg = "Unexpected error code #{resp.status} #{ERROR_SUFFIX}"
          raise Signet::AuthorizationError, msg
        end
      end

      # Returns a clone of a_hash updated with the authoriation header
      def apply! a_hash, opts = {}
        token = make_token!
        a_hash[AUTH_METADATA_KEY] = "Bearer #{token}"
        a_hash
      end

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
          scope: @scope,
        }.merge(options)

        new_client = self.class.new options
        new_client.update!(options)
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
