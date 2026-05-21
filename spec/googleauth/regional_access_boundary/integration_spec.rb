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
require "googleauth/regional_access_boundary"

describe "RegionalAccessBoundary Integration" do
  # A minimal client that includes BaseClient
  class TestClient
    include Google::Auth::BaseClient
    
    attr_accessor :access_token
    attr_accessor :logger
    
    def initialize
      @access_token = "secret_token"
      @logger = nil
    end
    
    def token_type
      :access_token
    end
    
    def id_token
      "secret_id_token"
    end
    
    def regional_access_boundary_url
      "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test@example.com/allowedLocations"
    end
    
    def fetch_access_token! opts = {}
      # no-op
    end
    
    def needs_access_token?
      false
    end
    
    # BaseClient requires expires_within? to be implemented
    def expires_within? seconds
      false
    end
    
    def principal
      "test@example.com"
    end

    def supports_regional_access_boundary?
      true
    end
  end

  let(:client) { TestClient.new }
  let(:headers) { {} }
  let(:url) { "https://storage.googleapis.com/v1/b/my-bucket" }
  let(:cache) { Google::Auth::RegionalAccessBoundary::Cache.new }

  before do
    # Stub the module-level cache to use our isolated test cache
    allow(Google::Auth::RegionalAccessBoundary).to receive(:cache).and_return(cache)
  end

  describe "applying headers" do
    it "does not attach header on cold start but triggers fetch" do
      # Stub Thread.new to yield immediately, running the fetch in the main thread
      # to avoid WebMock thread-safety issues and ensure predictable test execution.
      allow(Thread).to receive(:new).and_yield
      
      stub_request(:get, /allowedLocations/)
        .to_return(status: 200, body: MultiJson.dump({ "encodedLocations" => "0xABC" }))
        
      client.apply! headers, url: url
      
      expect(headers["x-allowed-locations"]).to be_nil
      expect(cache.should_fetch?).to be_falsey # It should be marked as fetching
    end

    it "attaches header when cache is populated" do
      data = Google::Auth::RegionalAccessBoundary::RegionalAccessBoundaryData.new "0xABC"
      cache.set data, 60
      
      client.apply! headers, url: url
      
      expect(headers["x-allowed-locations"]).to eq "0xABC"
    end

    it "skips lookup for regional endpoints" do
      regional_url = "https://storage.rep.googleapis.com/v1/b/my-bucket"
      
      client.apply! headers, url: regional_url
      
      expect(headers["x-allowed-locations"]).to be_nil
      expect(cache.should_fetch?).to be_truthy # Should not have marked as fetching
    end

    it "skips lookup for STS and IAM endpoints" do
      sts_url = "https://sts.googleapis.com/v1/token"
      client.apply! headers, url: sts_url
      expect(headers["x-allowed-locations"]).to be_nil
      expect(cache.should_fetch?).to be_truthy

      headers.clear # Reset headers
      iam_url = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test@example.com:generateAccessToken"
      client.apply! headers, url: iam_url
      expect(headers["x-allowed-locations"]).to be_nil
      expect(cache.should_fetch?).to be_truthy
    end

    it "fails open if lookup raises error" do
      mock_fetcher = double("Fetcher")
      allow(Google::Auth::RegionalAccessBoundary::Fetcher).to receive(:new).and_return(mock_fetcher)
      allow(mock_fetcher).to receive(:fetch).and_raise(Google::Auth::AuthorizationError, "Network error")
      
      # We need to make sure the thread executes synchronously or we join it to see the error handled
      # In implementation, we will use Thread.new. In test, we can stub Thread.new to execute immediately!
      
      allow(Thread).to receive(:new).and_yield
      
      client.apply! headers, url: url
      
      expect(headers["x-allowed-locations"]).to be_nil
      expect(cache.should_fetch?).to be_falsey # Should be in cooldown
    end

    it "skips lookup for unsupported credential types" do
      allow(client).to receive(:supports_regional_access_boundary?).and_return(false)
      
      client.apply! headers, url: url
      
      expect(headers["x-allowed-locations"]).to be_nil
      expect(cache.should_fetch?).to be_truthy # Should not have marked as fetching
    end

    it "skips lookup for ID tokens" do
      allow(client).to receive(:token_type).and_return(:id_token)
      
      client.apply! headers, url: url
      
      expect(headers["x-allowed-locations"]).to be_nil
      expect(cache.should_fetch?).to be_truthy # Should not have marked as fetching
    end
  end
end
