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

require "googleauth"
require "googleauth/web_user_authorizer"
require "uri"
require "multi_json"
require "spec_helper"
require "rack"

describe Google::Auth::WebUserAuthorizer do
  include TestHelpers

  let(:client_id) { Google::Auth::ClientId.new "testclient", "notasecret" }
  let(:scope) { %w[email profile] }
  let(:token_store) { DummyTokenStore.new }
  let :authorizer do
    Google::Auth::WebUserAuthorizer.new client_id, scope, token_store
  end

  describe "#get_authorization_url" do
    let :env do
      Rack::MockRequest.env_for(
        "http://example.com:8080/test",
        "REMOTE_ADDR" => "10.10.10.10"
      )
    end
    let(:request) { Rack::Request.new env }
    
    it "should raise InitializationError if request is nil" do
      expect { authorizer.get_authorization_url }.to raise_error do |error|
        expect(error).to be_a(Google::Auth::InitializationError)
        expect(error.message).to eq("Request is required.")
      end
    end
    
    it "should raise InitializationError if session is nil" do
      req_without_session = double("request", session: nil)
      expect { authorizer.get_authorization_url(request: req_without_session) }.to raise_error do |error|
        expect(error).to be_a(Google::Auth::InitializationError)
        expect(error.message).to eq("Sessions must be enabled")
      end
    end
    
    it "should include current url in state" do
      url = authorizer.get_authorization_url request: request
      expect(url).to match(
        %r{%22current_uri%22:%22http://example.com:8080/test%22}
      )
    end

    it "should allow adding custom state key-value pairs" do
      url = authorizer.get_authorization_url request: request, state: { james: "bond", kind: 1 }
      expect(url).to match(%r{%22james%22:%22bond%22})
      expect(url).to match(%r{%22kind%22:1})
    end

    it "should include request forgery token in state" do
      expect(SecureRandom).to receive(:base64).and_return("aGVsbG8=")
      url = authorizer.get_authorization_url request: request
      expect(url).to match(/%22session_id%22:%22aGVsbG8=%22/)
    end

    it "should include request forgery token in session" do
      expect(SecureRandom).to receive(:base64).and_return("aGVsbG8=")
      authorizer.get_authorization_url request: request
      expect(request.session["g-xsrf-token"]).to eq "aGVsbG8="
    end

    it "should resolve callback against base URL" do
      url = authorizer.get_authorization_url request: request
      expect(url).to match(
        %r{redirect_uri=http://example.com:8080/oauth2callback}
      )
    end

    it "should allow overriding the current URL" do
      url = authorizer.get_authorization_url(
        request:     request,
        redirect_to: "/foo"
      )
      expect(url).to match %r{%22current_uri%22:%22/foo%22}
    end

    it "should pass through login hint" do
      url = authorizer.get_authorization_url(
        request:    request,
        login_hint: "user@example.com"
      )
      expect(url).to match(/login_hint=user@example.com/)
    end

    it "should include code_challenge and code_challenge_method" do
      authorizer.code_verifier = Google::Auth::WebUserAuthorizer.generate_code_verifier
      url = authorizer.get_authorization_url(request: request)
      expect(url).to match(/code_challenge=/)
      expect(url).to match(/code_challenge_method=S256/)
    end
  end

  shared_examples "handles callback" do
    let :token_json do
      MultiJson.dump("access_token" => "1/abc123",
                     "token_type"   => "Bearer",
                     "expires_in"   => 3600)
    end

    before :example do
      stub_request(:post, "https://oauth2.googleapis.com/token")
        .to_return(body:    token_json,
                   status:  200,
                   headers: { "Content-Type" => "application/json" })
    end

    let :env do
      Rack::MockRequest.env_for(
        "http://example.com:8080/oauth2callback?code=authcode&"\
        "state=%7B%22current_uri%22%3A%22%2Ffoo%22%2C%22"\
        "session_id%22%3A%22abc%22%7D",
        "REMOTE_ADDR" => "10.10.10.10"
      )
    end
    let(:request) { Rack::Request.new env }

    before :example do
      request.session["g-xsrf-token"] = "abc"
    end

    it "should return credentials when valid code present" do
      expect(credentials).to be_instance_of(
        Google::Auth::UserRefreshCredentials
      )
    end

    it "should return next URL to redirect to" do
      expect(next_url).to eq "/foo"
    end

    it "should fail with AuthorizationError with detailed information if xrsf token in session and does not match request" do
      request.session["g-xsrf-token"] = "123"
      expect { credentials }.to raise_error do |error|
        expect(error).to be_a(Google::Auth::AuthorizationError)
        expect(error.message).to match(/State token does not match expected value/)
        expect(error.credential_type_name).to eq("Google::Auth::WebUserAuthorizer")
        expect(error.principal).to eq(:web_user_authorization)
      end
    end
  end
  

  describe "#handle_auth_callback" do
    let(:result) { authorizer.handle_auth_callback "user1", request }
    let(:credentials) { result[0] }
    let(:next_url) { result[1] }

    it_behaves_like "handles callback"
    
    context "when code is missing from request" do
      let :env do
        Rack::MockRequest.env_for(
          "http://example.com:8080/oauth2callback?"\
          "state=%7B%22current_uri%22%3A%22%2Ffoo%22%2C%22"\
          "session_id%22%3A%22abc%22%7D",
          "REMOTE_ADDR" => "10.10.10.10"
        )
      end
      
      let(:request) { Rack::Request.new env }
      
      before :example do
        request.session["g-xsrf-token"] = "abc"
      end
      
      it "should fail with AuthorizationError with detailed information" do
        expect { authorizer.handle_auth_callback "user1", request }.to raise_error do |error|
          expect(error).to be_a(Google::Auth::AuthorizationError)
          expect(error.message).to match(/Missing authorization code in request/)
          expect(error.credential_type_name).to eq("Google::Auth::WebUserAuthorizer")
          expect(error.principal).to eq(:web_user_authorization)
        end
      end
    end
    
    context "when error is present in callback state" do
      let :env do
        Rack::MockRequest.env_for(
          "http://example.com:8080/oauth2callback?error=access_denied&code=authcode&"\
          "state=%7B%22current_uri%22%3A%22%2Ffoo%22%2C%22"\
          "session_id%22%3A%22abc%22%7D",
          "REMOTE_ADDR" => "10.10.10.10"
        )
      end
      
      let(:request) { Rack::Request.new env }
      
      before :example do
        request.session["g-xsrf-token"] = "abc"
      end
      
      it "should fail with AuthorizationError with detailed information" do
        expect { authorizer.handle_auth_callback "user1", request }.to raise_error do |error|
          expect(error).to be_a(Google::Auth::AuthorizationError)
          expect(error.message).to match(/Authorization error: access_denied/)
          expect(error.credential_type_name).to eq("Google::Auth::WebUserAuthorizer")
          expect(error.principal).to eq(:web_user_authorization)
        end
      end
    end
  end

  describe "#handle_auth_callback_deferred and #get_credentials" do
    let :next_url do
      Google::Auth::WebUserAuthorizer.handle_auth_callback_deferred request
    end

    let :credentials do
      next_url
      authorizer.get_credentials "user1", request
    end

    it_behaves_like "handles callback"
    
    context "when code is missing from request" do
      let :env do
        Rack::MockRequest.env_for(
          "http://example.com:8080/oauth2callback?"\
          "state=%7B%22current_uri%22%3A%22%2Ffoo%22%2C%22"\
          "session_id%22%3A%22abc%22%7D",
          "REMOTE_ADDR" => "10.10.10.10"
        )
      end
      
      let(:request) { Rack::Request.new env }
      
      before :example do
        request.session["g-xsrf-token"] = "abc"
        Google::Auth::WebUserAuthorizer.handle_auth_callback_deferred request
      end
      
      it "should fail with AuthorizationError with detailed information" do
        expect { authorizer.get_credentials "user1", request }.to raise_error do |error|
          expect(error).to be_a(Google::Auth::AuthorizationError)
          expect(error.message).to match(/Missing authorization code in request/)
          expect(error.credential_type_name).to eq("Google::Auth::WebUserAuthorizer")
          expect(error.principal).to eq(:web_user_authorization)
        end
      end
    end
    
    context "when error is present in callback state" do
      let :env do
        Rack::MockRequest.env_for(
          "http://example.com:8080/oauth2callback?error=access_denied&code=authcode&"\
          "state=%7B%22current_uri%22%3A%22%2Ffoo%22%2C%22"\
          "session_id%22%3A%22abc%22%7D",
          "REMOTE_ADDR" => "10.10.10.10"
        )
      end
      
      let(:request) { Rack::Request.new env }
      
      before :example do
        request.session["g-xsrf-token"] = "abc"
        Google::Auth::WebUserAuthorizer.handle_auth_callback_deferred request
      end
      
      it "should fail with AuthorizationError with detailed information" do
        expect { authorizer.get_credentials "user1", request }.to raise_error do |error|
          expect(error).to be_a(Google::Auth::AuthorizationError)
          expect(error.message).to match(/Authorization error: access_denied/)
          expect(error.credential_type_name).to eq("Google::Auth::WebUserAuthorizer")
          expect(error.principal).to eq(:web_user_authorization)
        end
      end
    end
  end
end
