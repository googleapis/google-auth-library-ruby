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

require "spec_helper"
require "googleauth"
require "googleauth/regional_access_boundary/cache"

describe Google::Auth::RegionalAccessBoundary::Cache do
  let(:cache) { described_class.new }
  let(:key1) { "https://example.com/sa1/allowedLocations" }
  let(:key2) { "https://example.com/sa2/allowedLocations" }

  describe "#get" do
    it "returns nil when empty" do
      expect(cache.get(key1)).to be_nil
    end

    it "returns data when set" do
      data = double("Data")
      cache.set key1, data, 60
      expect(cache.get(key1)).to eq data
    end

    it "returns nil after expiry" do
      data = double("Data")
      cache.set key1, data, 1
      sleep 2
      expect(cache.get(key1)).to be_nil
    end
  end

  describe "#should_fetch?" do
    it "returns true when empty" do
      expect(cache.should_fetch?(key1)).to be_truthy
    end

    it "returns false when fetching" do
      cache.try_mark_fetching!(key1)
      expect(cache.should_fetch?(key1)).to be_falsey
    end

    it "returns true when fetching but PID changed (fork)" do
      cache.try_mark_fetching!(key1)
      # Simulate fork by stubbing Process.pid
      allow(Process).to receive(:pid).and_return(Process.pid + 1)
      expect(cache.should_fetch?(key1)).to be_truthy
    end
  end

  describe "#try_mark_fetching!" do
    it "returns true when empty and transitions to fetching" do
      expect(cache.try_mark_fetching!(key1)).to be_truthy
      # Subsequent attempts should return false because it's already fetching
      expect(cache.try_mark_fetching!(key1)).to be_falsey
    end

    it "returns true when fetching but PID changed (fork)" do
      expect(cache.try_mark_fetching!(key1)).to be_truthy
      # Simulate fork by stubbing Process.pid
      allow(Process).to receive(:pid).and_return(Process.pid + 1)
      expect(cache.try_mark_fetching!(key1)).to be_truthy
    end
  end

  describe "#mark_unsupported!" do
    it "prevents get and should_fetch? permanently" do
      data = double("Data")
      cache.set key1, data, 60
      expect(cache.get(key1)).to eq data

      cache.mark_unsupported!(key1)

      expect(cache.get(key1)).to be_nil
      expect(cache.should_fetch?(key1)).to be_falsey
      expect(cache.try_mark_fetching!(key1)).to be_falsey
    end
  end

  describe "multi-key isolation" do
    it "keeps data and fetching states completely isolated between distinct keys" do
      data1 = double("Data 1")
      data2 = double("Data 2")

      cache.set key1, data1, 7200
      cache.set key2, data2, 7200

      expect(cache.get(key1)).to eq data1
      expect(cache.get(key2)).to eq data2

      # Mark key1 as fetching
      expect(cache.try_mark_fetching!(key1)).to be_falsey # because it already has valid data (TTL 7200)
      
      # Let's expire key1 to test fetching
      cache.set key1, data1, -1 # Expired
      expect(cache.should_fetch?(key1)).to be_truthy
      expect(cache.should_fetch?(key2)).to be_falsey # key2 is still valid

      expect(cache.try_mark_fetching!(key1)).to be_truthy
      expect(cache.should_fetch?(key1)).to be_falsey
      expect(cache.should_fetch?(key2)).to be_falsey # key2 remains unaffected
    end

    it "isolates unsupported states between distinct keys" do
      cache.mark_unsupported!(key1)
      expect(cache.should_fetch?(key1)).to be_falsey
      expect(cache.should_fetch?(key2)).to be_truthy # key2 is still eligible to fetch
    end
  end
end
