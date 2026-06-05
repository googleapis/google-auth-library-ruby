# Copyright 2023 Google, Inc.
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

require "google/logging/message"
require "googleauth/regional_access_boundary"
require "googleauth/helpers/connection"

module Google
  # Module Auth provides classes that provide Google-specific authorization
  # used to access Google APIs.
  module Auth
    # BaseClient is a class used to contain common methods that are required by any
    # Credentials Client, including AwsCredentials, ServiceAccountCredentials,
    # and UserRefreshCredentials. This is a superclass of Signet::OAuth2::Client
    # and has been created to create a generic interface for all credentials clients
    # to use, including ones which do not inherit from Signet::OAuth2::Client.
    module BaseClient
      AUTH_METADATA_KEY = :authorization

      # Updates a_hash updated with the authentication token
      def apply! a_hash, opts = {}
        # fetch the access token there is currently not one, or if the client
        # has expired
        fetch_access_token! opts if needs_access_token?
        token = send token_type
        a_hash[AUTH_METADATA_KEY] = "Bearer #{token}"
        logger&.debug do
          hash = Digest::SHA256.hexdigest token
          Google::Logging::Message.from message: "Sending auth token. (sha256:#{hash})"
        end

        apply_regional_access_boundary! a_hash, opts

        a_hash[AUTH_METADATA_KEY]
      end

      # Whether this credential type supports Regional Access Boundaries.
      # Default is false. Override in specific credentials to enable.
      def supports_regional_access_boundary?
        false
      end

      # Returns a clone of a_hash updated with the authentication token
      def apply a_hash, opts = {}
        a_copy = a_hash.clone
        apply! a_copy, opts
        a_copy
      end

      # Whether the id_token or access_token is missing or about to expire.
      def needs_access_token?
        send(token_type).nil? || expires_within?(60)
      end

      # Returns a reference to the #apply method, suitable for passing as
      # a closure
      def updater_proc
        proc { |a_hash, opts = {}| apply a_hash, opts }
      end

      def on_refresh &block
        @refresh_listeners = [] unless defined? @refresh_listeners
        @refresh_listeners << block
      end

      def notify_refresh_listeners
        listeners = defined?(@refresh_listeners) ? @refresh_listeners : []
        listeners.each do |block|
          block.call self
        end
      end

      def expires_within?
        raise NoMethodError, "expires_within? not implemented"
      end

      # The logger used to log operations on this client, such as token refresh.
      attr_accessor :logger

      # @private
      def principal
        raise NoMethodError, "principal not implemented"
      end

      private

      def apply_regional_access_boundary! a_hash, opts
        return unless should_apply_rab? opts

        cache = Google::Auth::RegionalAccessBoundary.cache
        header_val = cache.get&.encoded_locations

        # For global endpoints, attach the x-allowed-locations header
        # to the outbound HTTP request if and only if a valid cache entry exists.
        a_hash["x-allowed-locations"] = header_val if header_val

        # Return early if credentials do not support RAB or if we can't transition to fetching.
        return unless respond_to?(:regional_access_boundary_url) && cache.try_mark_fetching!

        # Initiate an asynchronous, non-blocking lookup if a global request is
        # made and the cache is invalid or expired.
        trigger_async_rab_fetch cache
      end

      def should_apply_rab? opts
        # Return early if not supported by credential type or if ID token.
        return false unless token_type != :id_token && supports_regional_access_boundary?

        url = opts[:url]
        # URLs matching rep.googleapis.com are regional. Fallback to assume global if URL is not provided.
        is_global = url.nil? || !url.to_s.match?(/\.rep\.googleapis\.com|\.rep\.sandbox\.googleapis\.com/)

        # Return early if it's a regional endpoint
        return false unless is_global

        url_str = url.to_s
        # No need to attach headers/metadata for requests to the STS or IAM endpoints.
        is_excluded = url_str.match? %r{\Ahttps://(iam|iamcredentials|sts)\.googleapis\.com}

        # Return early if it's an excluded service (STS/IAM).
        !is_excluded
      end

      def trigger_async_rab_fetch cache
        Thread.new do
          begin
            lookup_url = regional_access_boundary_url

            # A nil or empty URL means we cannot attempt the lookup yet (e.g. waiting
            # for metadata server).
            if lookup_url && !lookup_url.empty?
              fetcher = Google::Auth::RegionalAccessBoundary::Fetcher.new rab_connection, lookup_url, self
              data = fetcher.fetch
              cache.set data, 6 * 60 * 60 # 6 hours
            else
              log_rab_warning "Regional Access Boundary lookup skipped: " \
                              "could not determine allowedLocations URL"
              cache.mark_fetch_failed!
            end
          rescue StandardError => e
            # Ensure that any failure during the asynchronous lookup (network error, IAM refusal, etc.) does
            # not propagate to the primary request or cause the application to crash.
            log_rab_warning "Regional Access Boundary lookup failed: #{e.class} - #{e.message}"
            cache.mark_fetch_failed!
          end
        end
      end

      def log_rab_warning msg
        logger&.warn do
          Google::Logging::Message.from(
            message: msg,
            "credentialsId" => object_id
          )
        end
      end

      def token_type
        raise NoMethodError, "token_type not implemented"
      end

      def fetch_access_token!
        raise NoMethodError, "fetch_access_token! not implemented"
      end

      # Returns the Faraday connection to use for Regional Access Boundary lookups.
      #
      # Respects the credentials-specific connection configuration if available,
      # falling back to the global default connection to align with the rest of the library.
      def rab_connection
        # Use the client-specific custom connection builder if present (used by Signet).
        conn = build_default_connection if respond_to? :build_default_connection
        # Use the credentials-specific connection if present (used by External Account credentials).
        conn ||= connection if respond_to? :connection
        # Fall back to the global configured default connection.
        conn || Google::Auth::Helpers::Connection.connection
      end
      private :rab_connection
    end
  end
end
