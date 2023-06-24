# Copyright 2023 Google, Inc.
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

require 'webmock/rspec'
require 'googleauth'
require 'googleauth/external_account/pluggable_credentials'

include Google::Auth::CredentialsLoader

CLIENT_ID = "username"
CLIENT_SECRET = "password"
# Base64 encoding of "username:password".
BASIC_AUTH_ENCODING = "dXNlcm5hbWU6cGFzc3dvcmQ="
SERVICE_ACCOUNT_EMAIL = "service-1234@service-name.iam.gserviceaccount.com"
SERVICE_ACCOUNT_IMPERSONATION_URL_BASE = "https://us-east1-iamcredentials.googleapis.com"
SERVICE_ACCOUNT_IMPERSONATION_URL_ROUTE = "/v1/projects/-/serviceAccounts/#{SERVICE_ACCOUNT_EMAIL}:generateAccessToken"
SERVICE_ACCOUNT_IMPERSONATION_URL = SERVICE_ACCOUNT_IMPERSONATION_URL_BASE + SERVICE_ACCOUNT_IMPERSONATION_URL_ROUTE
QUOTA_PROJECT_ID = "QUOTA_PROJECT_ID"
SCOPES = ["scope1", "scope2"]
SUBJECT_TOKEN_FIELD_NAME = "access_token"

TOKEN_URL = "https://sts.googleapis.com/v1/token"
TOKEN_INFO_URL = "https://sts.googleapis.com/v1/introspect"
SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
AUDIENCE = "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID"
DEFAULT_UNIVERSE_DOMAIN = "googleapis.com"

describe Google::Auth::ExternalAccount::PluggableAuthCredentials do
  PluggableAuthCredentials = Google::Auth::ExternalAccount::PluggableAuthCredentials
  CREDENTIAL_SOURCE_EXECUTABLE_COMMAND = "/fake/external/excutable --arg1=value1 --arg2=value2"
  CREDENTIAL_SOURCE_EXECUTABLE_OUTPUT_FILE = "fake_output_file"
  CREDENTIAL_SOURCE_EXECUTABLE = {
    "command": CREDENTIAL_SOURCE_EXECUTABLE_COMMAND,
    "timeout_millis": 30000,
    "output_file": CREDENTIAL_SOURCE_EXECUTABLE_OUTPUT_FILE,
  }
  CREDENTIAL_SOURCE = {"executable": CREDENTIAL_SOURCE_EXECUTABLE}
  EXECUTABLE_OIDC_TOKEN = "FAKE_ID_TOKEN"
  EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_ID_TOKEN = {
    "version": 1,
    "success": true,
    "token_type": "urn:ietf:params:oauth:token-type:id_token",
    "id_token": EXECUTABLE_OIDC_TOKEN,
    "expiration_time": 9999999999,
  }
  EXECUTABLE_SUCCESSFUL_OIDC_NO_EXPIRATION_TIME_RESPONSE_ID_TOKEN = {
    "version": 1,
    "success": true,
    "token_type": "urn:ietf:params:oauth:token-type:id_token",
    "id_token": EXECUTABLE_OIDC_TOKEN,
  }
  EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_JWT = {
    "version": 1,
    "success": true,
    "token_type": "urn:ietf:params:oauth:token-type:jwt",
    "id_token": EXECUTABLE_OIDC_TOKEN,
    "expiration_time": 9999999999,
  }
  EXECUTABLE_SUCCESSFUL_OIDC_NO_EXPIRATION_TIME_RESPONSE_JWT = {
    "version": 1,
    "success": true,
    "token_type": "urn:ietf:params:oauth:token-type:jwt",
    "id_token": EXECUTABLE_OIDC_TOKEN,
  }
  EXECUTABLE_SAML_TOKEN = "FAKE_SAML_RESPONSE"
  EXECUTABLE_SUCCESSFUL_SAML_RESPONSE = {
    "version": 1,
    "success": true,
    "token_type": "urn:ietf:params:oauth:token-type:saml2",
    "saml_response": EXECUTABLE_SAML_TOKEN,
    "expiration_time": 9999999999,
  }
  EXECUTABLE_SUCCESSFUL_SAML_NO_EXPIRATION_TIME_RESPONSE = {
    "version": 1,
    "success": true,
    "token_type": "urn:ietf:params:oauth:token-type:saml2",
    "saml_response": EXECUTABLE_SAML_TOKEN,
  }
  EXECUTABLE_FAILED_RESPONSE = {
    "version": 1,
    "success": false,
    "code": "401",
    "message": "Permission denied. Caller not authorized",
  }
  CREDENTIAL_URL = "http://fakeurl.com"

  #####################
  #
  #  Test Cases
  #
  #####################

  describe "test initialization" do
    examples = [
      {
        name: "from full options",
        options: {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :token_info_url => nil,
          :service_account_impersonation_url => nil,
          :service_account_impersonation_options => {},
          :client_id => nil,
          :client_secret => nil,
          :credential_source => CREDENTIAL_SOURCE,
          :quota_project_id => nil,
          :workforce_pool_user_project => nil,
          :universe_domain => DEFAULT_UNIVERSE_DOMAIN,
        },
        expect_result: PluggableAuthCredentials
      },
      {
        :name => "from required options",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => CREDENTIAL_SOURCE,
        },
        :expect_result => PluggableAuthCredentials
      },
      {
        :name => "Missing executable source",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => {},
        },
        :expect_error => /Missing excutable source. An 'executable' must be provided/
      },
      {
        :name => "Missing executable command",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => { executable: {} },
        },
        :expect_error => /Missing command field. Executable command must be provided./
      },
      {
        :name => "Timeout shorter than lower bound",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => {
            executable: {
              command: "dummy command",
              timeout_millis: 2000,
            }
          },
        },
        :expect_error => /Timeout must be between 5 and 120 seconds./
      },
      {
        :name => "Timeout longer than upper bound",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => {
            executable: {
              command: "dummy command",
              timeout_millis: 120001,
            }
          },
        },
        :expect_error => /Timeout must be between 5 and 120 seconds./
      },
    ]
    examples.each do |example|
      it example[:name] do
        if example[:expect_error].nil?
          expect(PluggableAuthCredentials.new example[:options]).to be_a(example[:expect_result])
        else
          expect{PluggableAuthCredentials.new example[:options]}.to raise_error(example[:expect_error])
        end
      end
    end
  end

  describe "test retrieve subject token failed on not enabled" do
    options = {
      :audience => AUDIENCE,
      :subject_token_type => SUBJECT_TOKEN_TYPE,
      :token_url => TOKEN_URL,
      :credential_source => CREDENTIAL_SOURCE,
    }
    credentials = PluggableAuthCredentials.new options
    it 'not enabled' do
      expect{credentials.retrieve_subject_token!}.to raise_error(/Executables need to be explicitly allowed/)
    end
  end

  describe "test retrieve subject token from cache file" do
    examples = [
      {
        :name => "id token",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => {
            :executable => {
              :command => "command",
              :output_file => "id_token_cache"
            }
          }
        },
        :file_content => MultiJson.dump(EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_ID_TOKEN),
        :expect_token => EXECUTABLE_OIDC_TOKEN
      },
      {
        :name => "jwt token",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => {
            :executable => {
              :command => "command",
              :output_file => "jwt_token_cache"
            }
          }
        },
        :file_content => MultiJson.dump(EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_JWT),
        :expect_token => EXECUTABLE_OIDC_TOKEN
      },
      {
        :name => "smal token",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => {
            :executable => {
              :command => "command",
              :output_file => "saml_token_cache"
            }
          }
        },
        :file_content => MultiJson.dump(EXECUTABLE_SUCCESSFUL_SAML_RESPONSE),
        :expect_token => EXECUTABLE_SAML_TOKEN
      }
    ]
    examples.each do |example|
      before :example do
        file_path = example[:options][:credential_source][:executable][:output_file]
        allow(File).to receive(:exist?).with(file_path).and_return(true)
        allow(File).to receive(:read).with(file_path, encoding: "utf-8").and_return(example[:file_content])
        ENV[Google::Auth::ExternalAccount::PluggableAuthCredentials::ENABLE_PLUGGABLE_ENV] = "1"
      end
      it example[:name] do
        credentials = PluggableAuthCredentials.new example[:options]
        expect(credentials.retrieve_subject_token!).to eql(example[:expect_token])
      end
    end
  end
end