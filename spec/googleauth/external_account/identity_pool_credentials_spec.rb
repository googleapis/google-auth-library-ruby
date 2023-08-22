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
require 'googleauth/external_account/identity_pool_credentials'

include Google::Auth::CredentialsLoader

CLIENT_ID = 'username'
CLIENT_SECRET = 'password'
# Base64 encoding of 'username:password'
BASIC_AUTH_ENCODING = 'dXNlcm5hbWU6cGFzc3dvcmQ='
SERVICE_ACCOUNT_EMAIL = 'service-1234@service-name.iam.gserviceaccount.com'

QUOTA_PROJECT_ID = 'QUOTA_PROJECT_ID'
SCOPES = ['scope1', 'scope2']
CONFIG_ROOT = 'TEST_CONFIG_ROOT'
SUBJECT_TOKEN_TEXT_FILE = File.join CONFIG_ROOT, 'external_subject_token.txt'
SUBJECT_TOKEN_JSON_FILE = File.join CONFIG_ROOT, 'external_subject_token.json'
SUBJECT_TOKEN_FIELD_NAME = 'access_token'

TOKEN_URL = 'https://sts.googleapis.com/v1/token'
TOKEN_INFO_URL = 'https://sts.googleapis.com/v1/introspect'
SUBJECT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:jwt'
AUDIENCE = '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID'
WORKFORCE_AUDIENCE = (
    '//iam.googleapis.com/locations/global/workforcePools/POOL_ID/providers/PROVIDER_ID'
)
WORKFORCE_SUBJECT_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:id_token'
WORKFORCE_POOL_USER_PROJECT = 'WORKFORCE_POOL_USER_PROJECT_NUMBER'

SERVICE_ACCOUNT_IMPERSONATION_URL_BASE = 'https://us-east1-iamcredentials.googleapis.com'
SERVICE_ACCOUNT_IMPERSONATION_URL_ROUTE = "/v1/projects/-/serviceAccounts/#{SERVICE_ACCOUNT_EMAIL}:generateAccessToken"
SERVICE_ACCOUNT_IMPERSONATION_URL = SERVICE_ACCOUNT_IMPERSONATION_URL_BASE + SERVICE_ACCOUNT_IMPERSONATION_URL_ROUTE

describe Google::Auth::ExternalAccount::IdentityPoolCredentials do
  ExternalAccountCredential = Google::Auth::ExternalAccount::IdentityPoolCredentials

  CREDENTIAL_SOURCE_TEXT = {'file': SUBJECT_TOKEN_TEXT_FILE}
  CREDENTIAL_SOURCE_JSON = {
    'file': SUBJECT_TOKEN_JSON_FILE,
    'format': {'type': 'json', 'subject_token_field_name': 'access_token'},
  }
  CREDENTIAL_URL = 'http://dummyurl.com'
  CREDENTIAL_SOURCE_TEXT_URL = {'url': 'http://dummytexturl.com'}
  CREDENTIAL_SOURCE_JSON_URL = {
      'url': 'http://dummyjsonurl.com',
      'format': {'type': 'json', 'subject_token_field_name': 'access_token'},
  }
  SUCCESS_RESPONSE = {
    'access_token': 'ACCESS_TOKEN',
    'issued_token_type': 'urn:ietf:params:oauth:token-type:access_token',
    'token_type': 'Bearer',
    'expires_in': 3600,
    'scope': SCOPES.join(' '),
  }


  #####################
  #
  #  Test Cases
  #
  #####################

  describe "test initialization" do
    examples = [
      {
        :name => "from full options", 
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :token_info_url => TOKEN_INFO_URL,
          :service_account_impersonation_url => SERVICE_ACCOUNT_IMPERSONATION_URL,
          :service_account_impersonation => {"token_lifetime_seconds": 2800},
          :cliend_id => CLIENT_ID,
          :client_secert => CLIENT_SECRET,
          :quota_project_id => QUOTA_PROJECT_ID,
          :credential_source => CREDENTIAL_SOURCE_TEXT,
        },
        :expect_result => ExternalAccountCredential
      },
      {
        :name => "from required options",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => CREDENTIAL_SOURCE_TEXT,
        },
        :expect_result => ExternalAccountCredential
      },
      {
        :name => "workforce pool project",
        :options => {
          :audience => WORKFORCE_AUDIENCE,
          :subject_token_type => WORKFORCE_SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => CREDENTIAL_SOURCE_TEXT,
          :workforce_pool_user_project => WORKFORCE_POOL_USER_PROJECT,
        },
        :expect_result => ExternalAccountCredential
      },
      {
        :name => "invalid options environment id",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :token_info_url => TOKEN_INFO_URL,
          :credential_source => {
            :url => CREDENTIAL_URL,
            :environment_id => "aws1"
          },
        },
        :expect_error => /Invalid Identity Pool credential_source field 'environment_id'/,
      },
      {
        :name => "invalid options credential source format",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :token_info_url => TOKEN_INFO_URL,
          :credential_source => {
            :url => CREDENTIAL_URL,
            :format => {:type => "invalid"},
          },
        },
        :expect_error => /Invalid credential_source format/,
      },
      {
        :name => "invalid options missing field name",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :token_info_url => TOKEN_INFO_URL,
          :credential_source => {
            :url => CREDENTIAL_URL,
            :format => {:type => "json"},
          },
        },
        :expect_error => /Missing subject_token_field_name for JSON credential_source format/,
      },
      {
        :name => "invalid options file and url conflict",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :token_info_url => TOKEN_INFO_URL,
          :credential_source => {
            :url => CREDENTIAL_URL,
            :file => CREDENTIAL_SOURCE_TEXT
          },
        },
        :expect_error => /Ambiguous credential_source. 'file' is mutually exclusive with 'url'/,
      },
      {
        :name => "invalid options missing credential source",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :token_info_url => TOKEN_INFO_URL,
          :credential_source => {},
        },
        :expect_error => /Missing credential_source. A 'file' or 'url' must be provided./
      }
    ]

    examples.each do |example|
      it example[:name] do
        if example[:expect_error].nil?
          expect(ExternalAccountCredential.new example[:options]).to be_a(example[:expect_result])
        else
          expect{ExternalAccountCredential.new example[:options]}.to raise_error(example[:expect_error])
        end
      end
    end
  end

  describe "test retrieve file subject token" do
    examples = [
      {
        :name => "retrieve from text file",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => CREDENTIAL_SOURCE_TEXT,
        },
        :file_exists => true,
        :file_output => "ACCESS_TOKEN",
        :expect_result => "ACCESS_TOKEN",
      },
      {
        :name => "retrieve from json file",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => CREDENTIAL_SOURCE_JSON,
        },
        :file_exists => true,
        :file_output => MultiJson.dump(SUCCESS_RESPONSE),
        :expect_result => "ACCESS_TOKEN",
      },
      {
        :name => "file io error",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          #:credential_source => CREDENTIAL_SOURCE_JSON,
          :credential_source => {'file': 'some_file_1', 'format': {'type': 'json', 'subject_token_field_name': 'access_token'}}
        },
        :file_exists => true,
        :access_error => IOError,
        :expect_error => //,
      },
      {
        :name => "file not found",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          #:credential_source => CREDENTIAL_SOURCE_JSON,
          :credential_source => {'file': 'some_file_2', 'format': {'type': 'json', 'subject_token_field_name': 'access_token'}},
        },
        :file_exists => false,
        :expect_error => /was not found/,
      }
    ]
    examples.each do |example|
      before :example do
        file_path = example[:options][:credential_source][:file]
        allow(File).to receive(:exist?).with(file_path).and_return(example[:file_exists])
        if example[:access_error].nil?
          allow(File).to receive(:read).with(file_path, encoding: "utf-8").and_return(example[:file_output])
        else
          allow(File).to receive(:read).with(file_path, encoding: "utf-8").and_raise(example[:access_error])
        end
      end
      it example[:name] do
        credentials = ExternalAccountCredential.new example[:options]
        if example[:expect_error].nil?
          expect(credentials.retrieve_subject_token!).to eq(example[:expect_result])
        else
          expect{credentials.retrieve_subject_token!}.to raise_error(example[:expect_error])
        end
      end
    end
  end

  describe "test retrieve url subject token" do
    examples = [
      {
        :name => "retrieve text token from url",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => CREDENTIAL_SOURCE_TEXT_URL,
        },
        :url_response => {"status": 200, "body": "SUBJECT_TOKEN"},
        :expect_result => "SUBJECT_TOKEN",
      },
      {
        :name => "retireve json token from url",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => CREDENTIAL_SOURCE_JSON_URL,
        },
        :url_response => {"status": 200, "body": MultiJson.dump(SUCCESS_RESPONSE)},
        :expect_result => "ACCESS_TOKEN",
      },
      {
        :name => "http request error",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => {
            'url': 'http://dummy.json.url.com',
            'format': {'type': 'json', 'subject_token_field_name': 'access_token'},
          },
        },
        :http_error => Faraday::Error,
        :expect_error => /Error retrieving from credential url/,
      },
      {
        :name => "resource not found error",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => {
            'url': 'http://dummy.notfound.jsonurl.com',
            'format': {'type': 'json', 'subject_token_field_name': 'access_token'},
          },
        },
        :url_response => {"status": 404, "body": "resource not found"},
        :expect_error => /Unable to retrieve Identity Pool subject token/,
      },
      {
        :name => "parsing error",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => {
            'url': 'http://dummy.malform.jsonurl.com',
            'format': {'type': 'json', 'subject_token_field_name': 'access_token'},
          },
        },
        :url_response => {"status": 200, "body": "malformed response"},
        :expect_error => /Unable to parse subject_token from JSON resource/,
      },
      {
        :name => "parsing error",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => {
            'url': 'http://dummy.missing.token.jsonurl.com',
            'format': {'type': 'json', 'subject_token_field_name': 'access_token'},
          },
        },
        :url_response => {"status": 200, "body": MultiJson.dump({
          'issued_token_type': 'urn:ietf:params:oauth:token-type:access_token',
          'token_type': 'Bearer',
          'expires_in': 3600,
          'scope': SCOPES.join(' '),
        })},
        :expect_error => /Missing subject_token in the credential_source/,
      }
    ]
    examples.each do |example|
      before :example do
        url = example[:options][:credential_source][:url]
        if example[:http_error].nil?
          resp_status = example[:url_response][:status]
          resp_body = example[:url_response][:body]
          stub_request(:get, url).to_return status: resp_status, body: resp_body
        else
          stub_request(:get, url).to_raise example[:http_error]
        end
      end
      it example[:name] do
        credentials = ExternalAccountCredential.new example[:options]
        if example[:expect_error].nil?
          expect(credentials.retrieve_subject_token!).to eq(example[:expect_result])
        else
          expect{credentials.retrieve_subject_token!}.to raise_error(example[:expect_error])
        end
      end
    end
  end
end
