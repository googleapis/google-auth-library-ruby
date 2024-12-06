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

  describe "token helpers" do
    let(:token) { "1/abcdef1234567890" }
    before :example do
      @access_token_client = Signet::OAuth2::Client.new(
        access_token: token
      )
      @id_token_client = Signet::OAuth2::Client.new(
        target_audience: "https://pubsub.googleapis.com/",
        id_token:        token
      )
      @unexpired_id_token_client = Signet::OAuth2::Client.new(
        target_audience: "https://pubsub.googleapis.com/",
        id_token:        token,
        expires_in:      3600
      )
      @unexpired_access_token_client = Signet::OAuth2::Client.new(
        access_token: token,
        expires_in:   3600
      )
      @expired_id_token_client = Signet::OAuth2::Client.new(
        target_audience: "https://pubsub.googleapis.com/",
        id_token:        token,
        expires_in:      30
      )
      @expired_access_token_client = Signet::OAuth2::Client.new(
        access_token: token,
        expires_in:   30
      )
    end

    describe "#token_type" do
      it "returns :access_token if target_audience is missing" do
        expect(@access_token_client.token_type).to eq(:access_token)
      end

      it "returns :id_token if target_audience is present" do
        expect(@id_token_client.token_type).to eq(:id_token)
      end
    end

    describe "#needs_access_token?" do
      it "returns true if target_audience and access_token are missing" do
        expect(@client.needs_access_token?).to be true
      end

      it "returns true if target_audience is present and id_token is missing" do
        expect(@id_client.needs_access_token?).to be true
      end

      it "returns true if access_token and expires_at are present and expires within 60s" do
        expect(@expired_access_token_client.needs_access_token?).to be true
      end

      it "returns true if target_audience, id_token and expires_at are present and expires within 60s" do
        expect(@expired_id_token_client.needs_access_token?).to be true
      end

      it "returns false if access_token is present" do
        expect(@access_token_client.needs_access_token?).to be false
      end

      it "returns false if target_audience and id_token is present" do
        expect(@id_token_client.needs_access_token?).to be false
      end

      it "returns false if access_token and expires_at are present and expires in more than 60s" do
        expect(@unexpired_access_token_client.needs_access_token?).to be false
      end

      it "returns false if target_audience, id_token and expires_at are present and expires in more than 60s" do
        expect(@unexpired_id_token_client.needs_access_token?).to be false
      end
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

  describe "duplicates" do
    before :example do
      @base_creds = Signet::OAuth2::Client.new(
        token_credential_uri: "https://oauth2.googleapis.com/token",
        scope:                "https://www.googleapis.com/auth/cloud-platform",
        issuer:               "app@example.com",
        audience:             "https://oauth2.googleapis.com/token",
        signing_key:          @key
      )
      @creds = @base_creds.duplicate
    end

    it "should duplicate the authorization_uri" do
      expect(@creds.authorization_uri).to eq nil
      expect(@creds.duplicate({
        client_id: "test-client-id-2", 
        authorization_uri: "https://test-authorization-uri.example.com",
        redirect_uri: "https://test-redirect-uri.example.com"
      }).authorization_uri.to_s.start_with?("https://test-authorization-uri.example.com")).to be true
    end

    it "should duplicate the token_credential_uri" do
      expect(@creds.token_credential_uri.to_s).to eq "https://oauth2.googleapis.com/token"
      expect(@creds.duplicate(token_credential_uri: "test-token-credential-uri").token_credential_uri.to_s).to eq "test-token-credential-uri"
    end

    it "should duplicate the client_id" do
      expect(@creds.client_id).to eq nil
      expect(@creds.duplicate(client_id: "test-client-id-2").client_id).to eq "test-client-id-2"
    end

    it "should duplicate the scope" do
      expect(@creds.scope).to eq ["https://www.googleapis.com/auth/cloud-platform"]
      expect(@creds.duplicate(scope: ["https://www.googleapis.com/auth/devstorage.read_only"]).scope).to eq ["https://www.googleapis.com/auth/devstorage.read_only"]
    end

    it "should duplicate the target_audience" do
      expect(@creds.target_audience).to eq nil
      expect(@creds.duplicate(target_audience: "test-target-audience").target_audience).to eq "test-target-audience"
    end

    it "should duplicate the redirect_uri" do
      expect(@creds.redirect_uri).to eq nil
      expect(@creds.duplicate(redirect_uri: "https://test-redirect-uri.example.com").redirect_uri.to_s).to eq "https://test-redirect-uri.example.com"
    end

    it "should duplicate the username" do
      expect(@creds.username).to eq nil
      expect(@creds.duplicate(username: "test-username").username).to eq "test-username"
    end

    it "should duplicate the password" do
      expect(@creds.password).to eq nil
      expect(@creds.duplicate(password: "test-password").password).to eq "test-password"
    end

    it "should duplicate the issuer" do
      expect(@creds.issuer).to eq "app@example.com"
      expect(@creds.duplicate(issuer: "test-issuer").issuer).to eq "test-issuer"
    end

    it "should duplicate the person" do
      expect(@creds.person).to eq nil
      expect(@creds.duplicate(person: "test-person").person).to eq "test-person"
    end

    it "should duplicate the sub" do
      expect(@creds.sub).to eq nil
      expect(@creds.duplicate(sub: "test-sub").sub).to eq "test-sub"
    end

    it "should duplicate the audience" do
      expect(@creds.audience).to eq "https://oauth2.googleapis.com/token"
      expect(@creds.duplicate(audience: "test-audience").audience).to eq "test-audience"
    end

    it "should duplicate the signing_key" do
      expect(@creds.signing_key).to be_a OpenSSL::PKey::RSA
      expect(@creds.duplicate(signing_key: "test-signing-key").signing_key).to eq "test-signing-key"
    end

    it "should duplicate the extension_parameters" do
      expect(@creds.extension_parameters).to eq({})
      expect(@creds.duplicate(extension_parameters: {test: "test"}).extension_parameters).to eq({test: "test"})
    end

    it "should duplicate the additional_parameters" do
      expect(@creds.additional_parameters).to eq({})
      expect(@creds.duplicate(additional_parameters: {test: "test"}).additional_parameters).to eq({test: "test"})
    end

    it "should duplicate the access_type" do
      expect(@creds.access_type).to eq :offline
      expect(@creds.duplicate(access_type: :online).access_type).to eq :online
    end

    it "should duplicate the universe_domain" do
      expect(@creds.universe_domain).to eq nil
      expect(@creds.duplicate(universe_domain: "universe-domain.example.com").universe_domain).to eq "universe-domain.example.com"
    end
  end
end
