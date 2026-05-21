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
require "googleauth/regional_access_boundary/fetcher"
require "webmock/rspec"

describe Google::Auth::RegionalAccessBoundary::Fetcher do
  let(:client) { Faraday.new }
  let(:url) { "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/test@example.com/allowedLocations" }
  let(:token) { double("Token", value: "secret_token", type: "Bearer") }
  let(:fetcher) { described_class.new client, url, token }

  before do
    WebMock.enable!
  end

  after do
    WebMock.disable!
  end

  describe "#fetch" do
    it "returns RegionalAccessBoundaryData on success" do
      stub_request(:get, url)
        .with(headers: { "Authorization" => "Bearer secret_token" })
        .to_return(status: 200, body: '{"locations": ["us-central1"], "encodedLocations": "0xABC"}')

      data = fetcher.fetch
      expect(data).to be_a Google::Auth::RegionalAccessBoundary::RegionalAccessBoundaryData
      expect(data.encoded_locations).to eq "0xABC"
    end

    it "retries on 500" do
      stub_request(:get, url)
        .to_return(status: 500)
        .then.to_return(status: 200, body: '{"locations": ["us-central1"], "encodedLocations": "0xABC"}')

      allow(fetcher).to receive(:sleep)

      data = fetcher.fetch
      expect(data.encoded_locations).to eq "0xABC"
    end

    it "raises error on 400" do
      stub_request(:get, url).to_return(status: 400)
      expect { fetcher.fetch }.to raise_error(Google::Auth::AuthorizationError)
    end
  end
end
