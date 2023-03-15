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

require 'googleauth'
require 'googleauth/apply_auth_examples'
require 'googleauth/external_account'
require 'spec_helper'
require 'tempfile'

describe Google::Auth::ExternalAccount::Credentials do
  describe :is_token_url_valid? do
    VALID_URLS = [
      "https://sts.googleapis.com",
      "https://sts.mtls.googleapis.com",
      "https://us-east-1.sts.googleapis.com",
      "https://us-east-1.sts.mtls.googleapis.com",
      "https://US-EAST-1.sts.googleapis.com",
      "https://sts.us-east-1.googleapis.com",
      "https://sts.US-WEST-1.googleapis.com",
      "https://us-east-1-sts.googleapis.com",
      "https://US-WEST-1-sts.googleapis.com",
      "https://US-WEST-1-sts.mtls.googleapis.com",
      "https://us-west-1-sts.googleapis.com/path?query",
      "https://sts-us-east-1.p.googleapis.com",
      "https://sts-us-east-1.p.mtls.googleapis.com",
    ]

    INVALID_URLS = [
      nil,
      "https://iamcredentials.googleapis.com",
      "https://mtls.iamcredentials.googleapis.com",
      "sts.googleapis.com",
      "mtls.sts.googleapis.com",
      "mtls.googleapis.com",
      "https://",
      "http://sts.googleapis.com",
      "https://st.s.googleapis.com",
      "https://us-eas\t-1.sts.googleapis.com",
      "https:/us-east-1.sts.googleapis.com",
      "https:/us-east-1.mtls.sts.googleapis.com",
      "https://US-WE/ST-1-sts.googleapis.com",
      "https://sts-us-east-1.googleapis.com",
      "https://sts-US-WEST-1.googleapis.com",
      "testhttps://us-east-1.sts.googleapis.com",
      "https://us-east-1.sts.googleapis.comevil.com",
      "https://us-east-1.us-east-1.sts.googleapis.com",
      "https://us-ea.s.t.sts.googleapis.com",
      "https://sts.googleapis.comevil.com",
      "hhttps://us-east-1.sts.googleapis.com",
      "https://us- -1.sts.googleapis.com",
      "https://-sts.googleapis.com",
      "https://-mtls.googleapis.com",
      "https://us-east-1.sts.googleapis.com.evil.com",
      "https://sts.pgoogleapis.com",
      "https://p.googleapis.com",
      "https://sts.p.com",
      "https://sts.p.mtls.com",
      "http://sts.p.googleapis.com",
      "https://xyz-sts.p.googleapis.com",
      "https://sts-xyz.123.p.googleapis.com",
      "https://sts-xyz.p1.googleapis.com",
      "https://sts-xyz.p.foo.com",
      "https://sts-xyz.p.foo.googleapis.com",
      "https://sts-xyz.mtls.p.foo.googleapis.com",
      "https://sts-xyz.p.mtls.foo.googleapis.com",
    ]

    VALID_URLS.each do |token_url|
      describe token_url do
        it 'is valid' do
          expect(Google::Auth::ExternalAccount::Credentials.is_token_url_valid?(token_url)).to be(true)
        end
      end
    end

    INVALID_URLS.each do |token_url|
      describe token_url do
        it 'is invalid' do
          expect(Google::Auth::ExternalAccount::Credentials.is_token_url_valid?(token_url)).to be(false)
        end
      end
    end
  end

  describe :is_service_account_impersonation_url_valid? do
    VALID_URLS = [
      nil,
      "https://iamcredentials.googleapis.com",
      "https://us-east-1.iamcredentials.googleapis.com",
      "https://US-EAST-1.iamcredentials.googleapis.com",
      "https://iamcredentials.us-east-1.googleapis.com",
      "https://iamcredentials.US-WEST-1.googleapis.com",
      "https://us-east-1-iamcredentials.googleapis.com",
      "https://US-WEST-1-iamcredentials.googleapis.com",
      "https://us-west-1-iamcredentials.googleapis.com/path?query",
      "https://iamcredentials-us-east-1.p.googleapis.com",
    ]
    INVALID_URLS = [
      "https://sts.googleapis.com",
      "iamcredentials.googleapis.com",
      "https://",
      "http://iamcredentials.googleapis.com",
      "https://iamcre.dentials.googleapis.com",
      "https://us-eas\t-1.iamcredentials.googleapis.com",
      "https:/us-east-1.iamcredentials.googleapis.com",
      "https://US-WE/ST-1-iamcredentials.googleapis.com",
      "https://iamcredentials-us-east-1.googleapis.com",
      "https://iamcredentials-US-WEST-1.googleapis.com",
      "testhttps://us-east-1.iamcredentials.googleapis.com",
      "https://us-east-1.iamcredentials.googleapis.comevil.com",
      "https://us-east-1.us-east-1.iamcredentials.googleapis.com",
      "https://us-ea.s.t.iamcredentials.googleapis.com",
      "https://iamcredentials.googleapis.comevil.com",
      "hhttps://us-east-1.iamcredentials.googleapis.com",
      "https://us- -1.iamcredentials.googleapis.com",
      "https://-iamcredentials.googleapis.com",
      "https://us-east-1.iamcredentials.googleapis.com.evil.com",
      "https://iamcredentials.pgoogleapis.com",
      "https://p.googleapis.com",
      "https://iamcredentials.p.com",
      "http://iamcredentials.p.googleapis.com",
      "https://xyz-iamcredentials.p.googleapis.com",
      "https://iamcredentials-xyz.123.p.googleapis.com",
      "https://iamcredentials-xyz.p1.googleapis.com",
      "https://iamcredentials-xyz.p.foo.com",
      "https://iamcredentials-xyz.p.foo.googleapis.com",
    ]

    VALID_URLS.each do |impersonation_url|
      describe impersonation_url do
        it 'is valid' do
          expect(Google::Auth::ExternalAccount::Credentials.is_service_account_impersonation_url_valid?(impersonation_url)).to be(true)
        end
      end
    end

    INVALID_URLS.each do |impersonation_url|
      describe impersonation_url do
        it 'is invalid' do
          expect(Google::Auth::ExternalAccount::Credentials.is_service_account_impersonation_url_valid?(impersonation_url)).to be(false)
        end
      end
    end
  end

  describe :make_creds do
    it 'should be able to make aws credentials' do
      f = Tempfile.new('aws')
      begin
        f.write(MultiJson.dump({
          type: 'external_account',
          audience: '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID',
          subject_token_type: 'urn:ietf:params:aws:token-type:aws4_request',
          token_url: 'https://sts.googleapis.com/v1/token',
          credential_source: {
            'environment_id' => 'aws1',
            'region_url' => 'http://169.254.169.254/latest/meta-data/placement/availability-zone',
            'url' => 'http://169.254.169.254/latest/meta-data/iam/security-credentials',
            'regional_cred_verification_url' => 'https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15',
          }
        }))
        f.rewind
        expect(Google::Auth::ExternalAccount::Credentials.make_creds(json_key_io: f)).to be_a(Google::Auth::ExternalAccount::AwsCredentials)
      ensure
        f.close
        f.unlink
      end
    end

    [:audience, :subject_token_type, :token_url, :credential_source].each do |field|
      it "should raise an error when missing the #{field} field" do
        f = Tempfile.new('missing')
        begin
          creds = {
            type: 'external_account',
            audience: '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID',
            subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
            token_url: 'https://sts.googleapis.com/v1/token',
            credential_source: {},
          }
          creds.delete(field)
          f.write(MultiJson.dump(creds))
          f.rewind
          expect { Google::Auth::ExternalAccount::Credentials.make_creds(json_key_io: f) }.to raise_error(/the json is missing the #{field} field/)
        ensure
          f.close
          f.unlink
        end
      end
    end

    it 'should raise an error for invalid credentials' do
      f = Tempfile.new('invalid')
      begin
        f.write(MultiJson.dump({
          type: 'external_account',
          audience: '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID',
          subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
          token_url: 'https://sts.googleapis.com/v1/token',
          credential_source: {},
        }))
        f.rewind
        expect { Google::Auth::ExternalAccount::Credentials.make_creds(json_key_io: f) }.to raise_error(/aws is the only currently supported external account type/)
      ensure
        f.close
        f.unlink
      end
    end

    it 'should raise an error if called incorrectly' do
      expect { Google::Auth::ExternalAccount::Credentials.make_creds({
        type: 'external_account',
        audience: '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID',
      }) }.to raise_error(/A json file is required for external account credentials./)
    end
  end
end
