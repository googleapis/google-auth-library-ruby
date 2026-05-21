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
      class Cache
        include MonitorMixin

        def initialize
          super()
          @data = nil
          @expiry = nil
          @is_fetching = false
          @fetching_pid = nil
          @cooldown_expiry = nil
          @cooldown_duration = 15 * 60 # 15 minutes in seconds
        end

        # Returns the cached data if valid and not expired.
        def get
          synchronize do
            return nil if @data.nil?
            # Do NOT attach header if NOW >= expireTime; treat as cache miss & trigger async lookup.
            return nil if Time.now > @expiry
            @data
          end
        end

        # Sets the data in cache with a TTL.
        def set data, ttl
          synchronize do
            @data = data
            @expiry = Time.now + ttl
            @is_fetching = false
            @fetching_pid = nil
            @cooldown_expiry = nil
            @cooldown_duration = 15 * 60 # reset cooldown
          end
        end

        # Determines if a fetch should be initiated.
        def should_fetch?
          synchronize do
            # If fetching but PID changed, the fetching thread was lost in fork.
            return true if @is_fetching && @fetching_pid != Process.pid

            # If already fetching in this process, don't fetch again.
            return false if @is_fetching

            # Before starting a background lookup, verify the cooldown state; if active, skip the lookup attempt.
            # Cooldown check must come before data nil check to prevent hot loops on initial failure.
            return false if @cooldown_expiry && Time.now < @cooldown_expiry

            return true if @data.nil?
            return true if Time.now > @expiry # Hard expiry

            # Trigger refresh if NOW > expireTime - 1h; still attach header as data is valid.
            return true if Time.now > (@expiry - 3600)

            false
          end
        end

        # Marks the cache as currently fetching, recording the PID.
        def mark_fetching!
          synchronize do
            @is_fetching = true
            @fetching_pid = Process.pid
          end
        end

        # Marks the fetch as failed, triggering cooldown.
        def mark_fetch_failed!
          synchronize do
            @is_fetching = false
            @fetching_pid = nil

            # If a lookup fails with a non-retriable error (or after retry exhaustion), initiate a 15-minute cooldown period with exponential backoff (up to 6 hours).
            # Add random bounded jitter (half of base to full base)
            jitter = @cooldown_duration / 2 + rand(@cooldown_duration / 2)
            @cooldown_expiry = Time.now + jitter

            # Exponential backoff for the NEXT attempt, up to 6 hours max
            @cooldown_duration = [@cooldown_duration * 2, 6 * 60 * 60].min
          end
        end
      end
    end
  end
end
