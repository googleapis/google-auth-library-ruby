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
      #
      # @return [Boolean] true if Regional Access Boundary is supported, false otherwise.
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

      # Evaluates and applies Regional Access Boundary restrictions to the metadata.
      #
      # Design (Fail Open):
      # If no valid cache exists, the request proceeds without the x-allowed-locations header.
      # Any background thread fetch operations triggered run asynchronously so the primary
      # application thread remains unblocked.
      #
      # @private
      # @param a_hash [Hash] the metadata to update.
      # @param opts [Hash] options containing the target request URL.
      # @return [void]
      def apply_regional_access_boundary! a_hash, opts
        return unless should_apply_rab? opts
        return unless respond_to? :regional_access_boundary_url

        key = regional_access_boundary_url
        # If lookup URL is nil or empty, we cannot determine identity yet (fail open).
        return if key.nil? || key.to_s.empty?

        cache = Google::Auth::RegionalAccessBoundary.cache
        header_val = cache.get(key)&.encoded_locations

        # For global endpoints, attach the x-allowed-locations header
        # to the outbound HTTP request if and only if a valid cache entry exists.
        a_hash["x-allowed-locations"] = header_val if header_val

        # Return early if we cannot transition to fetching for this key.
        return unless cache.try_mark_fetching! key

        # Initiate an asynchronous, non-blocking lookup if a global request is
        # made and the cache is invalid or expired.
        trigger_async_rab_fetch cache, key
      end

      # Determines if a request is eligible for Regional Access Boundary restrictions.
      #
      # @private
      # @param opts [Hash] request options.
      # @return [Boolean] true if the header should be applied, false otherwise (failing open).
      def should_apply_rab? opts
        # Skip if credential is an ID token, or if it doesn't support RAB.
        return false if token_type == :id_token || !supports_regional_access_boundary?

        # Skip lookup for non-default universe domains.
        # A nil or empty universe domain is treated as GDU (googleapis.com).
        ud = universe_domain if respond_to? :universe_domain
        return false if ud && !ud.to_s.empty? && ud != "googleapis.com"

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

      # Triggers the asynchronous lookup for RAB allowed locations in a background thread.
      #
      # Design (Fail Open & Concurrency Resilience):
      # - Run inside a separate Thread so lookup latency does not delay the primary API call.
      # - Rescue all StandardErrors to ensure no background fetch failures propagate or crash the process.
      # - Use an `ensure` block with a `success` flag. If the thread crashes on a non-StandardError
      #   (like NoMemoryError, SystemStackError, or RSpec's WebMock NetConnectNotAllowedError) or is killed
      #   before completion, the `ensure` block will catch it and call `cache.mark_fetch_failed!` to reset
      #   the fetching flag and initiate a cooldown. This prevents the cache from being stuck in an
      #   indefinite fetching state (`@is_fetching = true`) which would block all future retries.
      #
      # @private
      # @param cache [Google::Auth::RegionalAccessBoundary::Cache] the cache instance.
      # @param key [String, Symbol] the lookup URL or sentinel key.
      # @return [Thread] the background thread instance.
      def trigger_async_rab_fetch cache, key
        Thread.new do
          success = false
          begin
            if key == :unsupported
              cache.mark_unsupported! key
              log_rab_debug "Regional Access Boundary lookup permanently skipped: " \
                              "identity is not a standard service account email"
            else
              conn = Google::Auth::Helpers::Connection.connection_for self
              fetcher = Google::Auth::RegionalAccessBoundary::Fetcher.new conn, key, self
              data = fetcher.fetch
              cache.set key, data, 6 * 60 * 60 # 6 hours
            end
            success = true
          rescue StandardError => e
            # Ensure that any failure during the asynchronous lookup (network error, IAM refusal, etc.) does
            # not propagate to the primary request or cause the application to crash.
            log_rab_debug "Regional Access Boundary lookup failed: #{e.class} - #{e.message}"
            cache.mark_fetch_failed! key
            success = true
          ensure
            # If the block was exited prematurely without setting success to true (e.g. if the thread
            # crashed on a non-StandardError or was killed), reset the fetching state and trigger a cooldown.
            cache.mark_fetch_failed! key unless success
          end
        end
      end

      def log_rab_debug msg
        logger&.debug do
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
    end
  end
end
