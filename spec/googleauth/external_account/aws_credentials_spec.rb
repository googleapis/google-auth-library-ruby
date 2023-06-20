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

require 'googleauth'
require 'googleauth/apply_auth_examples'
require 'googleauth/external_account/aws_credentials'
require 'spec_helper'

include Google::Auth::CredentialsLoader

describe Google::Auth::ExternalAccount::AwsCredentials do
  AwsCredentials = Google::Auth::ExternalAccount::AwsCredentials

  before :each do
   stub_const('ENV', {})
  end

  let :current_datetime do
    Time.now.utc.strftime('%Y-%m-%dT%H:%M:%SZ')
  end

  let :expiry_datetime do
    (Time.now + 3600).utc.strftime('%Y-%m-%dT%H:%M:%SZ')
  end

  let(:credentials) { AwsCredentials.new(cred_json) }

  let(:aws_metadata_role_name) { 'my-aws-metadata-role' }
  let(:aws_region) { 'us-east-1c' }
  let(:aws_access_key_id) { 'test' }
  let(:aws_secret_access_key) { 'test' }
  let(:aws_token) { 'test' }
  let(:region_url) { 'http://169.254.169.254/latest/meta-data/placement/availability-zone' }
  let(:security_credential_url) { 'http://169.254.169.254/latest/meta-data/iam/security-credentials' }
  let(:regional_cred_verification_url) { 'https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15' }
  let(:service_account_impersonation_url) { nil }
  let(:imdsv2_url) { nil }
  let(:imdsv2_token) { 'imdsv2_token' }

  let :cred_json do
    {
      type: 'external_account',
      audience: '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID',
      subject_token_type: 'urn:ietf:params:aws:token-type:aws4_request',
      service_account_impersonation_url: service_account_impersonation_url,
      token_url: 'https://sts.googleapis.com/v1/token',
      credential_source: aws_credential_source
    }.compact
  end

  let :aws_credential_source do
    {
      environment_id: 'aws1',
      region_url: region_url,
      url: security_credential_url,
      regional_cred_verification_url: regional_cred_verification_url,
      imdsv2_session_token_url: imdsv2_url
    }.compact
  end

  let :aws_security_credentials_response do
    {
      Code: 'Success',
      LastUpdated: current_datetime,
      Type: 'AWS-HMAC',
      AccessKeyId: aws_access_key_id,
      SecretAccessKey: aws_secret_access_key,
      Token: aws_token,
      Expiration: expiry_datetime
    }.compact
  end

  let :google_token_response do
    {
      "token_type" => "Bearer",
      "expires_in" => 3600,
      "issued_token_type" => "urn:ietf:params:aws:token-type:aws4_request",
    }
  end

  let :google_token_impersonation_response do
    {
      accessToken: "test",
      expireTime: expiry_datetime
    }
  end

  let :basic_aws_headers do
    {
      'Accept'=>'*/*',
      'Accept-Encoding'=>/.*/,
      'User-Agent'=>/Faraday v\d+\.\d+\.\d+/
    }
  end

  let :aws_headers do
    headers = basic_aws_headers.clone
    headers.merge!('x-aws-ec2-metadata-token' => imdsv2_token) if imdsv2_url
    headers
  end

  let :metadata_role_endpoint do
    return unless security_credential_url
    stub_request(:get, security_credential_url)
      .with(headers: aws_headers)
  end

  let :metadata_role_endpoint_success do
    return unless security_credential_url
    metadata_role_endpoint.to_return body: aws_metadata_role_name
  end

  let :metadata_role_endpoint_failure do
    return unless security_credential_url
    metadata_role_endpoint.to_return status: 400
  end

  let :security_credential_endpoint do
    return unless security_credential_url and aws_metadata_role_name
    stub_request(:get, "#{security_credential_url}/#{aws_metadata_role_name}")
      .with(headers: aws_headers)
  end

  let :security_credential_endpoint_success do
    return unless security_credential_url and aws_metadata_role_name
    security_credential_endpoint.to_return(
      body: MultiJson.dump(aws_security_credentials_response))
  end

  let :security_credential_endpoint_failure do
    return unless security_credential_url and aws_metadata_role_name
    security_credential_endpoint.to_return status: 400
  end

  let :region_endpoint do
    return unless region_url
    stub_request(:get, region_url)
      .with(headers: aws_headers)
  end

  let :region_endpoint_success do
    return unless region_url
    region_endpoint.to_return body: aws_region
  end

  let :region_endpoint_failure do
    return unless region_url
    region_endpoint.to_return status: 400
  end

  let :imdsv2_endpoint do
    return unless imdsv2_url
    stub_request(:put, imdsv2_url)
      .with(headers: basic_aws_headers.clone.merge(
        'X-Aws-Ec2-Metadata-Token-Ttl-Seconds'=>'300'))
  end

  let :imdsv2_endpoint_success do
    return unless imdsv2_url
    imdsv2_endpoint.to_return body: imdsv2_token
  end

  let :imdsv2_endpoint_failure do
    return unless imdsv2_url
    imdsv2_endpoint.to_return status: 400
  end

  def impersonation_endpoint access_token
    return unless access_token and service_account_impersonation_url
    @impersonation_endpoint = stub_request(:post, service_account_impersonation_url)
      .with(
        body: "{\"scope\":[\"https://www.googleapis.com/auth/iam\"]}",
        headers: {
          'Accept'=>'*/*',
          'Accept-Encoding'=>/.*/,
          'Authorization'=>"Bearer #{access_token}",
          'Content-Type'=>'application/json',
          'User-Agent'=>/Faraday v\d+\.\d+\.\d+/
        })
  end

  def impersonation_endpoint_success access_token
    return unless access_token and service_account_impersonation_url
    impersonation_endpoint(access_token).to_return(
      body: MultiJson.dump(google_token_impersonation_response.merge({
        "accessToken" => access_token
      }))
    )
  end

  def impersonation_endpoint_failure access_token
    return unless access_token and service_account_impersonation_url
    impersonation_endpoint(access_token).to_return status: 400
  end

  def google_cred_endpoint
    @token_endpoint = stub_request(:post, cred_json[:token_url])
  end

  def google_cred_endpoint_success access_token
    google_cred_endpoint.to_return(
      body: MultiJson.dump(google_token_response.merge({
        "access_token" => access_token
      }))
    )
  end

  def google_cred_endpoint_failure
    google_cred_endpoint.to_return status: 400
  end

  def make_auth_stubs opts
    impersonation_endpoint_success opts[:access_token]
    google_cred_endpoint_success opts[:access_token]
  end

  #####################
  #
  #  Test Cases
  #
  #####################

  describe 'when AWS variables are provided via URLs' do
    let(:imdsv2_url) { 'http://169.254.169.254/latest/api/token' }
    before :example do
      @client = credentials

      imdsv2_endpoint_success
      region_endpoint_success
      metadata_role_endpoint_success
      security_credential_endpoint_success
    end

    it_behaves_like "apply/apply! are OK"
  end

  describe 'when AWS variables are provided via environment' do
    let(:region_url) { nil }
    before :example do
      @client = credentials

      ENV[AWS_REGION_VAR] = aws_region
      ENV[AWS_ACCESS_KEY_ID_VAR] = aws_access_key_id
      ENV[AWS_SECRET_ACCESS_KEY_VAR] = aws_secret_access_key
    end

    it_behaves_like "apply/apply! are OK"
  end

  describe 'when AWS variables are provided via environment with default-region' do
    let(:region_url) { nil }
    before :example do
      @client = credentials

      ENV[AWS_DEFAULT_REGION_VAR] = aws_region
      ENV[AWS_ACCESS_KEY_ID_VAR] = aws_access_key_id
      ENV[AWS_SECRET_ACCESS_KEY_VAR] = aws_secret_access_key
    end

    it_behaves_like "apply/apply! are OK"
  end

  describe 'when a region is not provided' do
    let(:region_url) { nil }

    before :example do
      metadata_role_endpoint_success
      security_credential_endpoint_success
    end

    it 'raises an error' do
      make_auth_stubs access_token: 'token'
      expect { credentials.fetch_access_token! }.to raise_error(/region_url or region must be set for external account credentials/)
    end
  end

  describe 'when a security credentials are not provided' do
    let(:imdsv2_url) { 'http://169.254.169.254/latest/api/token' }
    let(:security_credential_url) { nil }
    before :example do
      imdsv2_endpoint_success
      region_endpoint_success
    end

    it 'raises an error' do
      make_auth_stubs access_token: 'token'
      expect { credentials.fetch_access_token! }.to raise_error(/Unable to determine the AWS metadata server security credentials endpoint/)
    end
  end

  describe 'with service account impersonation' do
    let(:imdsv2_url) { 'http://169.254.169.254/latest/api/token' }
    let(:service_account_impersonation_url) { 'https://us-east1-iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/service-1234@service-name.iam.gserviceaccount.com:generateAccessToken'}

    before :example do
      @client = credentials

      imdsv2_endpoint_success
      region_endpoint_success
      metadata_role_endpoint_success
      security_credential_endpoint_success
    end

    it_behaves_like "apply/apply! are OK" do
      let(:extra_checks) do
        expect(@impersonation_endpoint).to have_been_requested.times(1)
      end
    end
  end

  describe 'with faulty service account impersonation' do
    let(:imdsv2_url) { 'http://169.254.169.254/latest/api/token' }
    let(:service_account_impersonation_url) { 'https://us-east1-iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/service-1234@service-name.iam.gserviceaccount.com:generateAccessToken'}

    before :example do
      @client = credentials

      imdsv2_endpoint_success
      region_endpoint_success
      metadata_role_endpoint_success
      security_credential_endpoint_success
      google_cred_endpoint_success 'token'
      impersonation_endpoint_failure 'token'
    end

    it 'raises an error' do
      expect { credentials.fetch_access_token! }.to raise_error(/Service account impersonation failed with status 400/)
    end
  end

  describe 'with imdsv2' do
    let(:imdsv2_url) { 'http://169.254.169.254/latest/api/token' }

    before :example do
      @client = credentials

      imdsv2_endpoint_success
      region_endpoint_success
      metadata_role_endpoint_success
      security_credential_endpoint_success
      imdsv2_endpoint_success
    end

    it_behaves_like "apply/apply! are OK" do
      let :extra_checks do
        expect(imdsv2_endpoint).to have_been_requested.at_least_once
      end
    end
  end

  describe 'with imdsv2 and environment variables' do
    let(:imdsv2_url) { 'http://169.254.169.254/latest/api/token' }

    before :example do
      @client = credentials

      ENV[AWS_REGION_VAR] = aws_region
      ENV[AWS_ACCESS_KEY_ID_VAR] = aws_access_key_id
      ENV[AWS_SECRET_ACCESS_KEY_VAR] = aws_secret_access_key
      # imdsv2 endpoint not set, but shouldn't be called
    end

    it_behaves_like "apply/apply! are OK"
  end

  describe 'region failure' do
    let(:imdsv2_url) { 'http://169.254.169.254/latest/api/token' }

    before :example do
      imdsv2_endpoint_success
      region_endpoint_failure
      metadata_role_endpoint_success
      security_credential_endpoint_success
    end

    it 'raises an error' do
      expect { credentials.fetch_access_token! }.to raise_error(/Failed to retrieve AWS region/)
    end
  end

  describe 'IAM role failure' do
    let(:imdsv2_url) { 'http://169.254.169.254/latest/api/token' }

    before :example do
      imdsv2_endpoint_success
      region_endpoint_success
      metadata_role_endpoint_failure
    end

    it 'raises an error' do
      expect { credentials.fetch_access_token! }.to raise_error(/Failed to retrieve AWS IAM Role/)
    end
  end

  describe 'AWS credential failure' do
    let(:imdsv2_url) { 'http://169.254.169.254/latest/api/token' }

    before :example do
      imdsv2_endpoint_success
      region_endpoint_success
      metadata_role_endpoint_success
      security_credential_endpoint_failure
    end

    it 'raises an error' do
      expect { credentials.fetch_access_token! }.to raise_error(/Failed to retrieve AWS credential/)
    end
  end

  describe 'ipv6 region url' do
    let(:imdsv2_url) { 'http://[fd00:ec2::254]/latest/api/token' }
    let(:region_url) { 'http://[fd00:ec2::254]/latest/meta-data/placement/availability-zone' }

    before :example do
      @client = credentials

      imdsv2_endpoint_success
      region_endpoint_success
      metadata_role_endpoint_success
      security_credential_endpoint_success
    end

    it_behaves_like "apply/apply! are OK"
  end

  describe 'ipv6 cred verification url' do
    let(:imdsv2_url) { 'http://[fd00:ec2::254]/latest/api/token' }
    let(:security_credential_url) { 'http://[fd00:ec2::254]/latest/meta-data/iam/security-credentials' }

    before :example do
      @client = credentials

      imdsv2_endpoint_success
      region_endpoint_success
      metadata_role_endpoint_success
      security_credential_endpoint_success
    end

    it_behaves_like "apply/apply! are OK"
  end

  describe 'ipv6 imdsv2 url' do
    let(:imdsv2_url) { 'http://[fd00:ec2::254]/latest/api/token' }

    before :example do
      @client = credentials

      region_endpoint_success
      metadata_role_endpoint_success
      security_credential_endpoint_success
      imdsv2_endpoint_success
    end

    it_behaves_like "apply/apply! are OK"
  end

  describe 'regional cred verification url without ssl' do
    let(:imdsv2_url) { 'http://[fd00:ec2::254]/latest/api/token' }
    let(:regional_cred_verification_url) { 'http://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15' }

    before :example do
      imdsv2_endpoint_success
      region_endpoint_success
      metadata_role_endpoint_success
      security_credential_endpoint_success
    end

    it 'raises an error' do
      expect { credentials.fetch_access_token! }.to raise_error(/Invalid AWS service URL/)
    end
  end
end
