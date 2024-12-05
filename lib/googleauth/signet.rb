# Copyright 2015 Google, Inc.
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

require "base64"
require "json"
require "signet/oauth_2/client"
require "googleauth/base_client"

module Signet
  # OAuth2 supports OAuth2 authentication.
  module OAuth2
    # Signet::OAuth2::Client creates an OAuth2 client
    #
    # This reopens Client to add #apply and #apply! methods which update a
    # hash with the fetched authentication token.
    class Client
      include Google::Auth::BaseClient

      alias update_token_signet_base update_token!

      def update_token! options = {}
        options = deep_hash_normalize options
        id_token_expires_at = expires_at_from_id_token options[:id_token]
        options[:expires_at] = id_token_expires_at if id_token_expires_at
        update_token_signet_base options
        self.universe_domain = options[:universe_domain] if options.key? :universe_domain
        self
      end

      def configure_connection options
        @connection_info =
          options[:connection_builder] || options[:default_connection]
        self
      end

      # The token type as symbol, either :id_token or :access_token
      def token_type
        target_audience ? :id_token : :access_token
      end

      # Set the universe domain
      attr_accessor :universe_domain

      alias orig_fetch_access_token! fetch_access_token!
      def fetch_access_token! options = {}
        unless options[:connection]
          connection = build_default_connection
          options = options.merge connection: connection if connection
        end
        info = retry_with_error do
          orig_fetch_access_token! options
        end
        notify_refresh_listeners
        info
      end

      alias googleauth_orig_generate_access_token_request generate_access_token_request
      def generate_access_token_request options = {}
        parameters = googleauth_orig_generate_access_token_request options
        logger&.info do
          Google::Logging::Message.from(
            message: "Requesting access token from #{parameters['grant_type']}",
            "credentialsId" => object_id
          )
        end
        logger&.debug do
          Google::Logging::Message.from(
            message: "Token fetch params: #{parameters}",
            "credentialsId" => object_id
          )
        end
        parameters
      end

      def build_default_connection
        if !defined?(@connection_info)
          nil
        elsif @connection_info.respond_to? :call
          @connection_info.call
        else
          @connection_info
        end
      end

      def retry_with_error max_retry_count = 5
        retry_count = 0

        begin
          yield.tap { |resp| log_response resp }
        rescue StandardError => e
          if e.is_a?(Signet::AuthorizationError) || e.is_a?(Signet::ParseError)
            log_auth_error e
            raise e
          end

          if retry_count < max_retry_count
            log_transient_error e
            retry_count += 1
            sleep retry_count * 0.3
            retry
          else
            log_retries_exhausted e
            msg = "Unexpected error: #{e.inspect}"
            raise Signet::AuthorizationError, msg
          end
        end
      end

      private

      def expires_at_from_id_token id_token
        match = /^[\w=-]+\.([\w=-]+)\.[\w=-]+$/.match id_token.to_s
        return unless match
        json = JSON.parse Base64.urlsafe_decode64 match[1]
        return unless json.key? "exp"
        Time.at json["exp"].to_i
      rescue StandardError
        # Shouldn't happen unless we get a garbled ID token
        nil
      end

      def log_response token_response
        response_hash = JSON.parse token_response rescue {}
        if response_hash["access_token"]
          digest = Digest::SHA256.hexdigest response_hash["access_token"]
          response_hash["access_token"] = "(sha256:#{digest})"
        end
        if response_hash["id_token"]
          digest = Digest::SHA256.hexdigest response_hash["id_token"]
          response_hash["id_token"] = "(sha256:#{digest})"
        end
        Google::Logging::Message.from(
          message: "Received auth token response: #{response_hash}",
          "credentialsId" => object_id
        )
      end

      def log_auth_error err
        logger&.info do
          Google::Logging::Message.from(
            message: "Auth error when fetching auth token: #{err}",
            "credentialsId" => object_id
          )
        end
      end

      def log_transient_error err
        logger&.info do
          Google::Logging::Message.from(
            message: "Transient error when fetching auth token: #{err}",
            "credentialsId" => object_id
          )
        end
      end

      def log_retries_exhausted err
        logger&.info do
          Google::Logging::Message.from(
            message: "Exhausted retries when fetching auth token: #{err}",
            "credentialsId" => object_id
          )
        end
      end
    end
  end
end
