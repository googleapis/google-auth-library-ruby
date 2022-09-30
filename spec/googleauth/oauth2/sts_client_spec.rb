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

require "googleauth"
require "googleauth/oauth2/sts_client"
require "spec_helper"

spec_dir = File.expand_path File.join(File.dirname(__FILE__))
$LOAD_PATH.unshift spec_dir
$LOAD_PATH.uniq!

describe Google::Auth::OAuth2::STSClient do
  GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange".freeze
  RESOURCE = "https://api.example.com/".freeze
  AUDIENCE = "urn:example:cooperation-context".freeze
  REQUESTED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token".freeze
  SUBJECT_TOKEN = "HEADER.SUBJECT_TOKEN_PAYLOAD.SIGNATURE".freeze
  SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt".freeze
  TOKEN_EXCHANGE_ENDPOINT = "https://example.com/token.oauth2".freeze
  SUCCESS_RESPONSE = {
      "access_token": "ACCESS_TOKEN",
      "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
      "token_type": "Bearer",
      "expires_in": 3600,
      "scope": "scope1 scope2",
  }.freeze
  ERROR_RESPONSE = {
      "error": "invalid_request",
      "error_description": "Invalid subject token",
      "error_uri": "https://tools.ietf.org/html/rfc6749",
  }.freeze

  context "with valid parameters" do
    let :sts_client do
      Google::Auth::OAuth2::STSClient.new({token_exchange_endpoint: TOKEN_EXCHANGE_ENDPOINT})
    end

    it 'should successfully exchange a token with only required parameters' do
      stub_request(:post, TOKEN_EXCHANGE_ENDPOINT).to_return(status: 200, body: SUCCESS_RESPONSE.to_json)

      res = sts_client.exchange_token({
        grant_type: GRANT_TYPE,
        subject_token: SUBJECT_TOKEN,
        subject_token_type: SUBJECT_TOKEN_TYPE,
        audience: AUDIENCE,
        requested_token_type: REQUESTED_TOKEN_TYPE
      })

      expect(res["access_token"]).to eq(SUCCESS_RESPONSE[:access_token])
    end

    it 'should appropriately handle an error response' do
      stub_request(:post, TOKEN_EXCHANGE_ENDPOINT).to_return(status: 400, body: ERROR_RESPONSE.to_json)

      # Expect an exception to be raised
      expect {
        sts_client.exchange_token({
          grant_type: GRANT_TYPE,
          subject_token: SUBJECT_TOKEN,
          subject_token_type: SUBJECT_TOKEN_TYPE,
          audience: AUDIENCE,
          requested_token_type: REQUESTED_TOKEN_TYPE
        })
      }.to raise_error(/Token exchange failed with status 400/)
    end
  end

  context "with invalid parameters" do
    it 'should raise an error if the token exchange endpoint is not provided' do
      expect {
        Google::Auth::OAuth2::STSClient.new
      }.to raise_error(/Token exchange endpoint can not be nil/)
    end
  end
end
