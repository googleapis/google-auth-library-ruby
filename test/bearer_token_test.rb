# Copyright 2025 Google LLC
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
require "googleauth/bearer_token"
require "logger"
require "digest"

describe Google::Auth::BearerTokenCredentials do
  let(:token) { "test-bearer-token-12345" }
  let(:example_universe_domain) { "example.com" }
  let(:expires_at) { Time.now + 3600 } # 1 hour from now

  describe "#initialize" do
    it "creates with token and proper defaults" do
      creds = Google::Auth::BearerTokenCredentials.new token: token
      _(creds.token).must_equal token
      _(creds.universe_domain).must_equal "googleapis.com"
    end

    it "creates with custom universe domain" do
      creds = Google::Auth::BearerTokenCredentials.new(
        token: token,
        universe_domain: example_universe_domain
      )
      _(creds.universe_domain).must_equal example_universe_domain
    end

    it "creates with expires_at as Time object" do
      creds = Google::Auth::BearerTokenCredentials.new(token: token, expires_at: expires_at)
      _(creds.expires_at).must_equal expires_at
    end

    it "creates with expires_at as Numeric timestamp" do
      expires_at_seconds = expires_at.to_i
      creds = Google::Auth::BearerTokenCredentials.new(token: token, expires_at: expires_at_seconds)
      _(creds.expires_at).must_equal Time.at(expires_at_seconds)
    end

    it "raises if bearer token is missing" do
      expect do
        Google::Auth::BearerTokenCredentials.new
      end.must_raise ArgumentError
    end

    it "raises if bearer token is empty" do
      expect do
        Google::Auth::BearerTokenCredentials.new(token: "")
      end.must_raise ArgumentError
    end
  end

  describe "#apply!" do
    let(:creds) { Google::Auth::BearerTokenCredentials.new token: token }

    it "adds Authorization token header to hash" do
      md = { foo: "bar" }
      want = { foo: "bar", Google::Auth::BearerTokenCredentials::AUTH_METADATA_KEY => "Bearer #{token}" }
      md = creds.apply md
      _(md).must_equal want
    end

    it "logs (hashed token) when a logger is set, but not the raw token" do
      strio = StringIO.new
      logger = Logger.new strio
      creds.logger = logger
      creds.apply({})
      _(strio.string).wont_be:empty?

      hashed_token = Digest::SHA256.hexdigest(token)
      _(strio.string).must_include hashed_token
      _(strio.string).wont_include token
    end
  end

  describe "#duplicate" do
    let(:creds) { Google::Auth::BearerTokenCredentials.new token: token, expires_at: expires_at }

    it "creates a duplicate with same values" do
      dup = creds.duplicate
      _(dup.token).must_equal token
      _(dup.expires_at).must_equal expires_at
      _(dup.universe_domain).must_equal "googleapis.com"
    end

    it "allows overriding values" do
      new_expires_at = Time.now + 7200
      dup = creds.duplicate token: "new-token", expires_at: new_expires_at, universe_domain: example_universe_domain
      _(dup.token).must_equal "new-token"
      _(dup.expires_at).must_equal new_expires_at
      _(dup.universe_domain).must_equal example_universe_domain
    end
  end

  describe "#expires_within?" do
    let(:creds) { Google::Auth::BearerTokenCredentials.new token: token, expires_at: expires_at }

    it "returns true if after expiration" do
      _(creds.expires_within?(4000)).must_equal true # Check after expiration
    end

    it "returns false if before expiration" do
      _(creds.expires_within?(3000)).must_equal false # Check before expiration
    end

    it "returns false if no expiration is set" do
      creds_no_expires_at = Google::Auth::BearerTokenCredentials.new token: token
      _(creds_no_expires_at.expires_within?(3600)).must_equal false
    end
  end

  describe "#fetch_access_token!" do
    it "returns nil if not expired" do
      creds = Google::Auth::BearerTokenCredentials.new token: token, expires_at: expires_at
      _(creds.send(:fetch_access_token!)).must_be_nil
    end

    it "raises if token is expired" do
      expired_time = Time.now - 3600
      creds = Google::Auth::BearerTokenCredentials.new token: token, expires_at: expired_time
      expect do
        creds.send(:fetch_access_token!)
      end.must_raise StandardError
    end

    it "returns nil if no expiry is set" do
      creds = Google::Auth::BearerTokenCredentials.new token: token
      _(creds.send(:fetch_access_token!)).must_be_nil
    end
  end
end
