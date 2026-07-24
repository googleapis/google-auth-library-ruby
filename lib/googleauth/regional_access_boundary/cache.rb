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

require "monitor"

module Google
  module Auth
    module RegionalAccessBoundary
      # Cache stores and manages the lifecycle of Regional Access Boundary data.
      #
      # Concurrency & Multi-Tenancy Design:
      # To prevent cross-credential allowedLocations cache pollution in multi-tenant or
      # multi-credential applications, cache entries are isolated into a Hash keyed by
      # the credential's allowedLocations lookup URL (or the `:unsupported` sentinel).
      #
      # Key Composition & Collision Analysis:
      # - String Keys: The lookup URL is built using the service account email, which is
      #   globally unique across Google Cloud. Therefore, key collisions between different
      #   service accounts are impossible.
      # - Hash Collisions: Ruby's internal Hash class handles hash-code collisions using key
      #   equality (`#eql?` / `==`), ensuring separate keys never overwrite each other.
      # - Self-Impersonation: If a service account impersonates itself, the URL resolves to the
      #   same key, allowing safe cache sharing since they represent the same IAM identity.
      # - Symbol Keys: GKE non-email identities (e.g. `system:serviceaccount:...`) resolve to
      #   the `:unsupported` sentinel key. Sharing the same `:unsupported` cache key is safe
      #   and correct because all such identities share the exact same outcome (permanent bypass).
      #
      # Thread & Fork Safety:
      # Access to `@entries` and individual entry state is synchronized using a `Monitor` mutex.
      # Process forks are detected via `Process.pid` checking to reset stale background fetching threads.
      #
      # @private
      class Cache
        include MonitorMixin

        # Represents a single cache entry for a specific identity / Allowed Locations lookup URL.
        # @private
        class Entry
          attr_accessor :data
          attr_accessor :expiry
          attr_accessor :is_fetching
          attr_accessor :fetching_pid
          attr_accessor :cooldown_expiry
          attr_accessor :cooldown_duration
          attr_accessor :unsupported

          def initialize
            @data = nil
            @expiry = nil
            @is_fetching = false
            @fetching_pid = nil
            @cooldown_expiry = nil
            @cooldown_duration = 15 * 60 # 15 minutes in seconds
            @unsupported = false
          end
        end

        def initialize
          super()
          @entries = {}
        end

        # Returns the cached data if valid and not expired for the given key.
        #
        # @param key [String, Symbol] the lookup URL or sentinel key.
        # @return [Google::Auth::RegionalAccessBoundary::RegionalAccessBoundaryData, nil] the cached data,
        #     or nil if cache is empty or expired.
        def get key
          synchronize do
            entry = @entries[key]
            return nil unless entry
            return nil if entry.unsupported
            return nil if entry.data.nil?
            # Do NOT attach header if NOW >= expireTime; treat as cache miss & trigger async lookup.
            return nil if Time.now > entry.expiry
            entry.data
          end
        end

        # Sets the data in cache with a TTL for the given key.
        #
        # @param key [String, Symbol] the lookup URL or sentinel key.
        # @param data [Google::Auth::RegionalAccessBoundary::RegionalAccessBoundaryData] the data to cache.
        # @param ttl [Numeric] time-to-live in seconds.
        # @return [void]
        def set key, data, ttl
          synchronize do
            entry = (@entries[key] ||= Entry.new)
            entry.data = data
            entry.expiry = Time.now + ttl
            entry.is_fetching = false
            entry.fetching_pid = nil
            entry.cooldown_expiry = nil
            entry.cooldown_duration = 15 * 60 # reset cooldown
          end
        end

        # Determines if a fetch should be initiated for the given key.
        #
        # @param key [String, Symbol] the lookup URL or sentinel key.
        # @return [Boolean] true if a background fetch is needed, false otherwise.
        def should_fetch? key
          synchronize do
            entry = @entries[key]
            return true unless entry

            return false if entry.unsupported

            # If fetching but PID changed, the fetching thread was lost in fork.
            return true if entry.is_fetching && entry.fetching_pid != Process.pid

            # If already fetching in this process, don't fetch again.
            return false if entry.is_fetching

            # Before starting a background lookup, verify the cooldown state; if active, skip.
            return false if entry.cooldown_expiry && Time.now < entry.cooldown_expiry

            return true if entry.data.nil?
            return true if Time.now > entry.expiry # Hard expiry

            # Trigger refresh if NOW > expireTime - 1h; still attach header as data is valid.
            return true if Time.now > (entry.expiry - 3600)

            false
          end
        end

        # Attempts to transition the cache status to fetching if a fetch is needed.
        #
        # @param key [String, Symbol] the lookup URL or sentinel key.
        # @return [Boolean] true if successfully marked as fetching, false otherwise.
        def try_mark_fetching! key
          synchronize do
            if should_fetch? key
              entry = (@entries[key] ||= Entry.new)
              entry.is_fetching = true
              entry.fetching_pid = Process.pid
              true
            else
              false
            end
          end
        end

        # Marks the fetch as failed for the given key, triggering cooldown.
        #
        # @param key [String, Symbol] the lookup URL or sentinel key.
        # @return [void]
        def mark_fetch_failed! key
          synchronize do
            entry = (@entries[key] ||= Entry.new)
            entry.is_fetching = false
            entry.fetching_pid = nil

            # If a lookup fails with a non-retriable error (or after retry
            # exhaustion), initiate a 15-minute cooldown period with exponential
            # backoff (up to 6 hours).
            # Add random bounded jitter (half of base to full base)
            jitter = (entry.cooldown_duration / 2) + rand(entry.cooldown_duration / 2)
            entry.cooldown_expiry = Time.now + jitter

            # Exponential backoff for the NEXT attempt, up to 6 hours max
            entry.cooldown_duration = [entry.cooldown_duration * 2, 6 * 60 * 60].min
          end
        end

        # Marks the cache as permanently unsupported for the given key, bypassing future checks.
        #
        # @param key [String, Symbol] the lookup URL or sentinel key.
        # @return [void]
        def mark_unsupported! key
          synchronize do
            entry = (@entries[key] ||= Entry.new)
            entry.unsupported = true
            entry.is_fetching = false
            entry.fetching_pid = nil
          end
        end
      end
    end
  end
end
