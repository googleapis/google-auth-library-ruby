# Copyright 2024 Google LLC
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

require "helper"
require "googleauth/api_key"
require "logger"

describe Google::Auth::APIKeyCredentials do
  let(:api_key) { "test-api-key-12345" }
  let(:example_universe_domain) { "example.com" }

  describe "#initialize" do
    it "creates with an API key" do
      creds = Google::Auth::APIKeyCredentials.new api_key: api_key
      _(creds.api_key).must_equal api_key
      _(creds.universe_domain).must_equal "googleapis.com"
    end

    it "creates with custom universe domain" do
      creds = Google::Auth::APIKeyCredentials.new(
        api_key: api_key,
        universe_domain: example_universe_domain
      )
      _(creds.universe_domain).must_equal example_universe_domain
    end

    it "raises if API key is missing" do
      expect do
        Google::Auth::APIKeyCredentials.new
      end.must_raise ArgumentError
    end

    it "raises if API key is empty" do
      expect do
        Google::Auth::APIKeyCredentials.new(api_key: "")
      end.must_raise ArgumentError
    end
  end

  describe "#from_env" do
    after do
      ENV.delete Google::Auth::APIKeyCredentials::API_KEY_VAR
    end

    it "returns nil if environment variable not set" do
      ENV.delete Google::Auth::APIKeyCredentials::API_KEY_VAR
      creds = Google::Auth::APIKeyCredentials.from_env
      _(creds).must_be_nil
    end

    it "returns nil if environment variable empty" do
      ENV[Google::Auth::APIKeyCredentials::API_KEY_VAR] = ""
      creds = Google::Auth::APIKeyCredentials.from_env
      _(creds).must_be_nil
    end

    it "creates credentials from environment variable" do
      ENV[Google::Auth::APIKeyCredentials::API_KEY_VAR] = api_key
      creds = Google::Auth::APIKeyCredentials.from_env
      _(creds).must_be_instance_of Google::Auth::APIKeyCredentials
      _(creds.api_key).must_equal api_key
    end
  end

  describe "#apply!" do
    let(:creds) { Google::Auth::APIKeyCredentials.new api_key: api_key }

    it "adds API key header to hash" do
      md = { foo: "bar" }
      want = { :foo => "bar", Google::Auth::APIKeyCredentials::API_KEY_HEADER => api_key }
      md = creds.apply md
      _(md).must_equal want
    end

    it "logs when a logger is set" do
      strio = StringIO.new
      logger = Logger.new strio
      creds.logger = logger
      md = {}
      md = creds.apply md
      _(strio.string).wont_be :empty?
    end
  end

  describe "#token_type" do
    let(:creds) { Google::Auth::APIKeyCredentials.new api_key: api_key }

    it "returns :api_key" do
      _(creds.send(:token_type)).must_equal :api_key
    end
  end

  describe "#duplicate" do
    let(:creds) { Google::Auth::APIKeyCredentials.new api_key: api_key }

    it "creates a duplicate with same values" do 
      dup = creds.duplicate
      _(dup.api_key).must_equal api_key
      _(dup.universe_domain).must_equal "googleapis.com"
    end

    it "allows overriding values" do
      dup = creds.duplicate api_key: "new-key", universe_domain: example_universe_domain
      _(dup.api_key).must_equal "new-key"
      _(dup.universe_domain).must_equal example_universe_domain
    end
  end

  describe "#expires_within?" do
    let(:creds) { Google::Auth::APIKeyCredentials.new api_key: api_key }

    it "always returns false" do
      _(creds.expires_within?(60)).must_equal false
    end
  end
end
