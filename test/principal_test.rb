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

require "stringio"
require "multi_json"

require "googleauth/api_key"
require "googleauth/bearer_token"
require "googleauth/client_id"
require "googleauth/compute_engine"
require "googleauth/external_account"
require "googleauth/iam"
require "googleauth/service_account"
require "googleauth/service_account_jwt_header"
require "googleauth/impersonated_service_account"
require "googleauth/user_refresh"
require "googleauth/user_authorizer"

describe "Principal methods" do
  describe "APIKeyCredentials" do
    it "returns :api_key as principal" do
      creds = Google::Auth::APIKeyCredentials.new api_key: "test-api-key"
      _(creds.principal).must_equal :api_key
    end
  end

  describe "BearerTokenCredentials" do
    it "returns :bearer_token as principal" do
      creds = Google::Auth::BearerTokenCredentials.new token: "test-token"
      _(creds.principal).must_equal :bearer_token
    end
  end

  describe "GCECredentials" do
    it "returns :gce_metadata as principal" do
      creds = Google::Auth::GCECredentials.new
      _(creds.principal).must_equal :gce_metadata
    end
  end

  describe "IAMCredentials" do
    it "returns the selector as principal" do
      selector = "test-selector"
      creds = Google::Auth::IAMCredentials.new selector, "test-token"
      _(creds.principal).must_equal selector
    end
  end

  describe "ServiceAccountCredentials" do
    it "returns the issuer as principal" do
      test_email = "test-service-account@example.project.iam.gserviceaccount.com"
      json = {
        private_key:  @key = OpenSSL::PKey::RSA.new(2048).to_pem,
        client_email: test_email,
        type:         "service_account"
      }
      key_io = StringIO.new MultiJson.dump(json)
      creds = Google::Auth::ServiceAccountCredentials.make_creds json_key_io: key_io
      _(creds.principal).must_equal test_email
    end
  end

  describe "ServiceAccountJwtHeaderCredentials" do
    it "returns the issuer as principal" do
      test_email = "test-service-account@example.project.iam.gserviceaccount.com"
      json = {
        private_key:  @key = OpenSSL::PKey::RSA.new(2048).to_pem,
        client_email: test_email
      }
      key_io = StringIO.new MultiJson.dump(json)
      creds = Google::Auth::ServiceAccountJwtHeaderCredentials.make_creds json_key_io: key_io
      _(creds.principal).must_equal test_email
    end
  end

  describe "ImpersonatedServiceAccountCredentials" do
    it "returns the source principal when source has a principal method" do
      source_creds = Object.new
      def source_creds.updater_proc
        proc { |a_hash, _opts = {}| a_hash }
      end

      def source_creds.principal
        :custom_principal
      end

      test_impersonation_url = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/target@example.com:generateAccessToken"
      test_scope = ["https://www.googleapis.com/auth/userinfo.email"]
      creds = Google::Auth::ImpersonatedServiceAccountCredentials.new(
        source_credentials: source_creds,
        impersonation_url: test_impersonation_url,
        scope: test_scope
      )
      _(creds.principal).must_equal :custom_principal
    end

    it "returns :unknown when source doesn't have a principal method" do
      source_creds = Object.new
      def source_creds.updater_proc
        proc { |a_hash, _opts = {}| a_hash }
      end

      test_impersonation_url = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/target@example.com:generateAccessToken"
      test_scope = ["https://www.googleapis.com/auth/userinfo.email"]
      creds = Google::Auth::ImpersonatedServiceAccountCredentials.new(
        source_credentials: source_creds,
        impersonation_url: test_impersonation_url,
        scope: test_scope
      )
      _(creds.principal).must_equal :unknown
    end
  end

  describe "UserRefreshCredentials" do
    it "returns the client_id as principal when available" do
      test_client_id = "test-client-id.apps.googleusercontent.com"
      json = {
        client_id: test_client_id,
        client_secret: "notsosecret",
        refresh_token: "refreshing-token",
        type:          "authorized_user"
      }
      key_io = StringIO.new MultiJson.dump(json)
      creds = Google::Auth::UserRefreshCredentials.make_creds json_key_io: key_io
      _(creds.principal).must_equal test_client_id
    end

    it "returns :user_refresh when client_id not available" do
      # This isn't a typical initialization path, but we need to test the fallback
      creds = Google::Auth::UserRefreshCredentials.new
      _(creds.principal).must_equal :user_refresh
    end
  end

  describe "UserAuthorizer" do
    let :expected_client_id do
      "test-client-id.apps.googleusercontent.com"
    end

    let :client_id do
      Google::Auth::ClientId.new(
        expected_client_id,
        "notsosecret"
      )
    end

    it "returns the client id as principal" do
      scope = ["https://www.googleapis.com/auth/userinfo.email"]
      token_store = TestTokenStore.new
      authorizer = Google::Auth::UserAuthorizer.new(
        client_id,
        scope,
        token_store
      )
      _(authorizer.principal).must_equal expected_client_id
    end
  end

  describe "WebUserAuthorizer" do
    it "should return :web_user_authorization as the principal" do
      _(Google::Auth::WebUserAuthorizer.principal).must_equal :web_user_authorization
    end
  end

  describe "External Account Base Credentials" do
    it "returns audience as principal" do
      # Create a test class inline that includes the module
      test_class = Class.new do
        include Google::Auth::ExternalAccount::BaseCredentials

        attr_reader :audience

        def initialize audience
          @audience = audience
        end
      end

      test_audience = "//iam.googleapis.com/projects/test-project/locations/global/workforce-pools/test"
      creds = test_class.new test_audience
      _(creds.principal).must_equal test_audience
    end
  end
end
