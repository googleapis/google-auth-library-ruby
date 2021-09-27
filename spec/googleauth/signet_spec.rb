# Copyright 2015 Google, Inc.
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

spec_dir = File.expand_path File.join(File.dirname(__FILE__))
$LOAD_PATH.unshift spec_dir
$LOAD_PATH.uniq!

require "apply_auth_examples"
require "googleauth/signet"
require "jwt"
require "openssl"
require "spec_helper"

describe Signet::OAuth2::Client do
  before :example do
    @key = OpenSSL::PKey::RSA.new 2048
    @client = Signet::OAuth2::Client.new(
      token_credential_uri: "https://oauth2.googleapis.com/token",
      scope:                "https://www.googleapis.com/auth/userinfo.profile",
      issuer:               "app@example.com",
      audience:             "https://oauth2.googleapis.com/token",
      signing_key:          @key
    )
    @id_client = Signet::OAuth2::Client.new(
      token_credential_uri: "https://oauth2.googleapis.com/token",
      target_audience:      "https://pubsub.googleapis.com/",
      issuer:               "app@example.com",
      audience:             "https://oauth2.googleapis.com/token",
      signing_key:          @key
    )
  end

  def make_auth_stubs opts
    body_fields = { "token_type" => "Bearer", "expires_in" => 3600 }
    body_fields["access_token"] = opts[:access_token] if opts[:access_token]
    body_fields["id_token"] = opts[:id_token] if opts[:id_token]
    body = MultiJson.dump body_fields
    blk = proc do |request|
      params = Addressable::URI.form_unencode request.body
      claim, _header = JWT.decode(params.assoc("assertion").last,
                                  @key.public_key, true,
                                  algorithm: "RS256")
      !opts[:id_token] || claim["target_audience"] == "https://pubsub.googleapis.com/"
    end
    with_params = { body: hash_including(
      "grant_type" => "urn:ietf:params:oauth:grant-type:jwt-bearer"
    ) }
    with_params[:headers] = { "User-Agent" => opts[:user_agent] } if opts[:user_agent]
    stub_request(:post, "https://oauth2.googleapis.com/token")
      .with(with_params, &blk)
      .to_return(body:    body,
                 status:  200,
                 headers: { "Content-Type" => "application/json" })
  end

  it_behaves_like "apply/apply! are OK"

  describe "#configure_connection" do
    it "honors default_connection" do
      token = "1/abcdef1234567890"
      stub = make_auth_stubs access_token: token, user_agent: "RubyRocks/1.0"
      conn = Faraday.new headers: { "User-Agent" => "RubyRocks/1.0" }
      @client.configure_connection default_connection: conn
      md = { foo: "bar" }
      @client.apply! md
      want = { foo: "bar", authorization: "Bearer #{token}" }
      expect(md).to eq(want)
      expect(stub).to have_been_requested
    end

    it "honors connection_builder" do
      token = "1/abcdef1234567890"
      stub = make_auth_stubs access_token: token, user_agent: "RubyRocks/2.0"
      connection_builder = proc do
        Faraday.new headers: { "User-Agent" => "RubyRocks/2.0" }
      end
      @client.configure_connection connection_builder: connection_builder
      md = { foo: "bar" }
      @client.apply! md
      want = { foo: "bar", authorization: "Bearer #{token}" }
      expect(md).to eq(want)
      expect(stub).to have_been_requested
    end
  end

  describe "#fetch_access_token!" do
    it "retries when orig_fetch_access_token! raises Signet::RemoteServerError" do
      mocked_responses = [:raise, :raise, "success"]
      allow(@client).to receive(:orig_fetch_access_token!).exactly(3).times do
        response = mocked_responses.shift
        response == :raise ? raise(Signet::RemoteServerError) : response
      end
      expect(@client.fetch_access_token!).to eq("success")
    end

    it "raises when the max retry count is exceeded" do
      mocked_responses = [:raise, :raise, :raise, :raise, :raise, :raise, "success"]
      allow(@client).to receive(:orig_fetch_access_token!).exactly(6).times do
        response = mocked_responses.shift
        response == :raise ? raise(Signet::RemoteServerError) : response
      end
      expect { @client.fetch_access_token! }.to raise_error Signet::AuthorizationError
    end

    it "does not retry and raises right away if it encounters a Signet::AuthorizationError" do
      allow(@client).to receive(:orig_fetch_access_token!).at_most(:once)
        .and_raise(Signet::AuthorizationError.new("Some Message"))
      expect { @client.fetch_access_token! }.to raise_error Signet::AuthorizationError
    end

    it "does not retry and raises right away if it encounters a Signet::ParseError" do
      allow(@client).to receive(:orig_fetch_access_token!).at_most(:once).and_raise(Signet::ParseError)
      expect { @client.fetch_access_token! }.to raise_error Signet::ParseError
    end
  end
end
