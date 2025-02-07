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
  let(:expiry) { Time.now + 3600 } # 1 hour from now

  describe "#initialize" do
    it "creates with token and proper defaults" do
      creds = Google::Auth::BearerTokenCredentials.new token: token
      _(creds.token).must_equal token
      _(creds.token_type).must_equal :bearer_token
      _(creds.universe_domain).must_equal "googleapis.com"
    end

    it "creates with custom universe domain" do
      creds = Google::Auth::BearerTokenCredentials.new(
        token: token,
        universe_domain: example_universe_domain
      )
      _(creds.universe_domain).must_equal example_universe_domain
    end

    it "creates with expiry as Time object" do
      creds = Google::Auth::BearerTokenCredentials.new(token: token, expiry: expiry)
      _(creds.expiry).must_equal expiry
    end

    it "creates with expiry as Numeric timestamp" do
      expiry_seconds = expiry.to_i
      creds = Google::Auth::BearerTokenCredentials.new(token: token, expiry: expiry_seconds)
      _(creds.expiry).must_equal Time.at(expiry_seconds)
    end

    it "creates with custom token type" do
      creds = Google::Auth::BearerTokenCredentials.new(token: token, token_type: :access_token)
      _(creds.token_type).must_equal :access_token
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

    it "raises if invalid token type is provided" do
      expect do
        Google::Auth::BearerTokenCredentials.new(token: token, token_type: :invalid)
      end.must_raise ArgumentError
    end
  end

  describe "#apply!" do
    let(:creds) { Google::Auth::BearerTokenCredentials.new token: token }

    it "adds Authorization token header to hash" do
      md = { foo: "bar" }
      want = {:foo => "bar", Google::Auth::BearerTokenCredentials::AUTHORIZATION_HEADER_NAME => "Bearer #{token}" }
      md = creds.apply md
      _(md).must_equal want
    end

    it "Token type does not influence the header value" do
        creds = Google::Auth::BearerTokenCredentials.new token: token, token_type: :access_token
        md = { foo: "bar" }
        want = {:foo => "bar", Google::Auth::BearerTokenCredentials::AUTHORIZATION_HEADER_NAME => "Bearer #{token}" }
        md = creds.apply md
        _(md).must_equal want
    end

    it "logs (hashed token) when a logger is set" do
      strio = StringIO.new
      logger = Logger.new strio
      creds.logger = logger

      creds.apply({})

      _(strio.string).wont_be:empty?
      hashed_token = Digest::SHA256.hexdigest(token)
      _(strio.string).must_include hashed_token # Check if the hash is logged.
      _(strio.string).wont_include token # Explicitly check that the raw token is NOT logged.
    end
  end

  describe "#token_type" do
    it "defaults to :bearer_token" do
        creds = Google::Auth::BearerTokenCredentials.new token: token
        _(creds.token_type).must_equal :bearer_token
    end
    it "returns the provided token type" do
        creds = Google::Auth::BearerTokenCredentials.new token: token, token_type: :access_token
        _(creds.token_type).must_equal :access_token
    end
  end

  describe "#duplicate" do
    let(:creds) { Google::Auth::BearerTokenCredentials.new token: token, expiry: expiry, token_type: :access_token}

    it "creates a duplicate with same values" do
      dup = creds.duplicate
      _(dup.token).must_equal token
      _(dup.expiry).must_equal expiry
      _(dup.token_type).must_equal :access_token
      _(dup.universe_domain).must_equal "googleapis.com"
    end

    it "allows overriding values" do
      new_expiry = Time.now + 7200
      dup = creds.duplicate token: "new-token", expiry: new_expiry, token_type: :jwt, universe_domain: example_universe_domain
      _(dup.token).must_equal "new-token"
      _(dup.expiry).must_equal new_expiry
      _(dup.token_type).must_equal :jwt
      _(dup.universe_domain).must_equal example_universe_domain
    end
  end

  describe "#expires_within?" do
    let(:creds) { Google::Auth::BearerTokenCredentials.new token: token, expiry: expiry }

    it "returns true if after expiry" do
      _(creds.expires_within?(4000)).must_equal true # Check after expiry
    end

    it "returns false if before expiry" do
      _(creds.expires_within?(3000)).must_equal false # Check before expiry
    end

    it "returns false if no expiry is set" do
      creds_no_expiry = Google::Auth::BearerTokenCredentials.new token: token
      _(creds_no_expiry.expires_within?(3600)).must_equal false
    end
  end
end
