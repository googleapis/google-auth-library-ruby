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

  describe "#get" do
    it "returns nil when empty" do
      expect(cache.get).to be_nil
    end

    it "returns data when set" do
      data = double("Data")
      cache.set data, 60
      expect(cache.get).to eq data
    end

    it "returns nil after expiry" do
      data = double("Data")
      cache.set data, 1
      sleep 2
      expect(cache.get).to be_nil
    end
  end

  describe "#should_fetch?" do
    it "returns true when empty" do
      expect(cache.should_fetch?).to be_truthy
    end

    it "returns false when fetching" do
      cache.mark_fetching!
      expect(cache.should_fetch?).to be_falsey
    end

    it "returns true when fetching but PID changed (fork)" do
      cache.mark_fetching!
      # Simulate fork by stubbing Process.pid
      allow(Process).to receive(:pid).and_return(Process.pid + 1)
      expect(cache.should_fetch?).to be_truthy
    end
  end
end
