# Copyright 2022 Google, Inc.
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
require "googleauth/external_account"

include Google::Auth::CredentialsLoader

describe Google::Auth::ExternalAccountCredentials do
  ExternalAccountCredentials = Google::Auth::ExternalAccountCredentials

  let(:aws_metadata_role_name) { "aws-metadata-role" }
  let(:aws_region) { "us-east-1c" }

  let :cred_json do
    {
      type: "external_account",
      audience: "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID",
      subject_token_type: "urn:ietf:params:aws:token-type:aws4_request",
      service_account_impersonation_url: "https://us-east1-iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/service-1234@service-name.iam.gserviceaccount.com:generateAccessToken",
      token_url: "https://sts.googleapis.com/v1/token",
      credential_source: {
        environment_id: "aws1",
        region_url: "http://169.254.169.254/latest/meta-data/placement/availability-zone",
        url: "http://169.254.169.254/latest/meta-data/iam/security-credentials",
        regional_cred_verification_url: "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"
      }
    }
  end

  let :current_datetime do
    Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")
  end

  let :expiry_datetime do
    (Time.now + 3600).utc.strftime("%Y-%m-%dT%H:%M:%SZ")
  end

  let :aws_security_credentials_response do
    {
      Code: "Success",
      LastUpdated: current_datetime,
      Type: "AWS-HMAC",
      AccessKeyId: "test",
      SecretAccessKey: "test",
      Token: "test",
      Expiration: expiry_datetime
    }
  end

  let :google_token_response do
    {
      "token_type" => "Bearer",
      "expires_in" => 3600,
      "issued_token_type" => "urn:ietf:params:aws:token-type:aws4_request"
    }
  end

  let :google_token_impersonation_response do
    {
      accessToken: "test",
      expireTime: expiry_datetime
    }
  end

  before :example do
    # Stub the region request response that happens duing initialization. This cannot happen as
    # part of make_auth_stubs since this request is made during the before block.
    stub_request(:get, cred_json.dig(:credential_source, :region_url))
      .to_return(status: 200, body: aws_region, headers: {"Content-Type" => "text/plain"})
  end

  def cred_json_text
    MultiJson.dump cred_json
  end

  def cred_json_without_impersonation_url_text
    MultiJson.dump cred_json_without_impersonation_url
  end

  # Stubs the common requests to all external account credential types
  def make_auth_stubs opts
    # Stub the metadata role name request
    stub_request(:get, cred_json.dig(:credential_source, :url))
      .to_return(body:    aws_metadata_role_name,
                 status:  200,
                 headers: { "Content-Type" => "text/plain" }
      )

    # Stub the AWS security credentials request
    stub_request(:get, "#{cred_json.dig(:credential_source, :url)}/#{aws_metadata_role_name}")
      .with(headers: { "Content-Type" => "application/json" })
      .to_return(
        body: MultiJson.dump(aws_security_credentials_response)
      )

    # Stub the Google token request
    response = google_token_response
    response["access_token"] = opts[:access_token] if opts[:access_token]
    stub_request(:post, cred_json.dig(:token_url))
      .to_return(
        body: MultiJson.dump(response)
      )
  end

  describe "when a service impersonation URL is provided" do
    before :example do
      @client = ExternalAccountCredentials.make_creds(
        json_key_io: StringIO.new(cred_json_text),
        scope: "https://www.googleapis.com/auth/userinfo.profile"
      )
    end

    alias :orig_make_auth_stubs :make_auth_stubs
    def make_auth_stubs opts
      orig_make_auth_stubs opts

      # Stub the Google token impersonation request
      response = google_token_impersonation_response
      response["accessToken"] = opts[:access_token] if opts[:access_token]
      stub_request(:post, cred_json.dig(:service_account_impersonation_url))
        .to_return(
          body: MultiJson.dump(response)
        )
    end

    it_behaves_like "apply/apply! are OK"
  end

  describe "when a service impersonation URL is not provided" do
    let :cred_json_without_impersonation_url do
      cred_json.dup.tap { |c| c.delete :service_account_impersonation_url }
    end

    before :example do
      @client = ExternalAccountCredentials.make_creds(
        json_key_io: StringIO.new(cred_json_without_impersonation_url_text),
        scope: "https://www.googleapis.com/auth/userinfo.profile"
      )
    end

    it_behaves_like "apply/apply! are OK"
  end
end
