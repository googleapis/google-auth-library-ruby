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

require 'googleauth'
require 'googleauth/apply_auth_examples'
require 'googleauth/external_account'
require 'spec_helper'
require 'stringio'
require 'tempfile'

describe Google::Auth::ExternalAccount::Credentials do

  describe "universe_domain checks" do
    before :example do
      @tempfile = Tempfile.new("aws")
    end

    after :example do
      @tempfile.close
      @tempfile.unlink
    end

    def load_file options
      @tempfile.write(JSON.generate(options))
      @tempfile.rewind
      Google::Auth::ExternalAccount::Credentials.make_creds(json_key_io: @tempfile)
    end

    it "loads aws without custom domain" do
      creds = load_file({
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
      })
      expect(creds.universe_domain).to eq("googleapis.com")
    end

    it "loads aws with custom domain" do
      creds = load_file({
        type: 'external_account',
        audience: '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID',
        subject_token_type: 'urn:ietf:params:aws:token-type:aws4_request',
        token_url: 'https://sts.googleapis.com/v1/token',
        credential_source: {
          'environment_id' => 'aws1',
          'region_url' => 'http://169.254.169.254/latest/meta-data/placement/availability-zone',
          'url' => 'http://169.254.169.254/latest/meta-data/iam/security-credentials',
          'regional_cred_verification_url' => 'https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15',
        },
        universe_domain: "myuniverse.com"
      })
      expect(creds.universe_domain).to eq("myuniverse.com")
    end

    it "loads identity pool without custom domain" do
      creds = load_file({
        type: 'external_account',
        audience: '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID',
        subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        token_url: 'https://sts.googleapis.com/v1/token',
        credential_source: {
          'file' => 'external_suject_token.txt'
        }
      })
      expect(creds.universe_domain).to eq("googleapis.com")
    end

    it "loads identity pool with custom domain" do
      creds = load_file({
        type: 'external_account',
        audience: '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID',
        subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        token_url: 'https://sts.googleapis.com/v1/token',
        credential_source: {
          'file' => 'external_suject_token.txt'
        },
        universe_domain: "myuniverse.com"
      })
      expect(creds.universe_domain).to eq("myuniverse.com")
    end

    it "loads pluggable without custom domain" do
      creds = load_file({
        type: 'external_account',
        audience: '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID',
        subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        token_url: 'https://sts.googleapis.com/v1/token',
        credential_source: {
          executable: {
            command: 'dummy_command',
          },
        }
      })
      expect(creds.universe_domain).to eq("googleapis.com")
    end

    it "loads pluggable with custom domain" do
      creds = load_file({
        type: 'external_account',
        audience: '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID',
        subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
        token_url: 'https://sts.googleapis.com/v1/token',
        credential_source: {
          executable: {
            command: 'dummy_command',
          },
        },
        universe_domain: "myuniverse.com"
      })
      expect(creds.universe_domain).to eq("myuniverse.com")
    end
  end

  describe :make_creds do
    it 'should be able to make aws credentials' do
      f = Tempfile.new('aws')
      begin
        f.write(JSON.generate({
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

    it 'should be able to make identity pool credentials' do
      f = Tempfile.new('file')
      begin
        f.write(JSON.generate({
          type: 'external_account',
          audience: '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID',
          subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          token_url: 'https://sts.googleapis.com/v1/token',
          credential_source: {
            'file' => 'external_suject_token.txt'
          }
        }))
        f.rewind
        expect(Google::Auth::ExternalAccount::Credentials.make_creds(json_key_io: f)).to be_a(Google::Auth::ExternalAccount::IdentityPoolCredentials)
      ensure
        f.close
        f.unlink
      end
    end

    it 'should be able to make pluggable auth credentials' do
      f = Tempfile.new('file')
      begin
        f.write(JSON.generate({
          type: 'external_account',
          audience: '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID',
          subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          token_url: 'https://sts.googleapis.com/v1/token',
          credential_source: {
            executable: {
              command: 'dummy_command',
            },
          },
        }))
        f.rewind
        expect(Google::Auth::ExternalAccount::Credentials.make_creds(json_key_io: f)).to be_a(Google::Auth::ExternalAccount::PluggableAuthCredentials)
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
          f.write(JSON.generate(creds))
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
        f.write(JSON.generate({
          type: 'external_account',
          audience: '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID',
          subject_token_type: 'urn:ietf:params:oauth:token-type:id_token',
          token_url: 'https://sts.googleapis.com/v1/token',
          credential_source: {},
        }))
        f.rewind
        expect { Google::Auth::ExternalAccount::Credentials.make_creds(json_key_io: f) }.to raise_error(Google::Auth::ExternalAccount::Credentials::INVALID_EXTERNAL_ACCOUNT_TYPE)
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

    it 'should raise an error if the credential type is not external_account' do
      f = Tempfile.new('invalid_type')
      begin
        f.write(JSON.generate({
          type: 'service_account',
          audience: '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID',
          subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          token_url: 'https://sts.googleapis.com/v1/token',
          credential_source: {},
        }))
        f.rewind
        expect { Google::Auth::ExternalAccount::Credentials.make_creds(json_key_io: f) }
          .to raise_error(Google::Auth::InitializationError, /The provided credentials were not of type 'external_account'. Instead, the type was 'service_account'./)
      ensure
        f.close
        f.unlink
      end
    end

    it 'should succeed if the credential type is missing (uses default)' do
      f = Tempfile.new('missing_type')
      begin
        f.write(JSON.generate({
          audience: '//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID',
          subject_token_type: 'urn:ietf:params:oauth:token-type:jwt',
          token_url: 'https://sts.googleapis.com/v1/token',
          credential_source: {
            'file' => 'external_suject_token.txt'
          },
        }))
        f.rewind
        expect { Google::Auth::ExternalAccount::Credentials.make_creds(json_key_io: f) }
          .not_to raise_error(
            Google::Auth::InitializationError, /The provided credentials were not of type 'external_account'/
          )
      ensure
        f.close
        f.unlink
      end
    end
  end

  describe "project_id with universe_domain" do
    let(:custom_universe_domain) { "myuniverse.com" }
    let(:custom_crm_url) { "https://cloudresourcemanager.myuniverse.com/v1/projects/123456" }
    let(:default_crm_url) { "https://cloudresourcemanager.googleapis.com/v1/projects/123456" }
    let(:custom_sts_url) { "https://sts.myuniverse.com/v1/token" }
    let(:workload_audience) do
      "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID"
    end

    shared_examples "project_id resolution with custom universe_domain" do
      it "uses custom universe_domain when resolving project_id via Credentials.new" do
        custom_crm_stub = stub_request(:get, custom_crm_url)
                          .with(headers: { "Content-Type" => "application/json" })
                          .to_return(status: 200, body: JSON.generate(projectId: "my-custom-project"))
        default_crm_stub = stub_request(:get, default_crm_url)

        creds = Google::Auth::ExternalAccount::Credentials.make_creds(
          json_key_io: StringIO.new(JSON.generate(cred_config))
        )
        expect(creds).to be_a(expected_class)
        expect(creds.universe_domain).to eq(custom_universe_domain)

        wrapped_creds = Google::Auth::Credentials.new(creds)

        expect(wrapped_creds.project_id).to eq("my-custom-project")
        expect(custom_crm_stub).to have_been_requested.once
        expect(default_crm_stub).not_to have_been_requested
        expect(a_request(:any, %r{googleapis\.com})).not_to have_been_made
      end

      it "resolves project_id on subsequent Credentials.new after fetching access_token" do
        unauth_crm_stub = stub_request(:get, custom_crm_url)
                          .with(
                            headers: {
                              "Authorization" => /\ABearer\s*\z/,
                              "Content-Type" => "application/json"
                            }
                          )
                          .to_return(status: 401, body: "")
        auth_crm_stub = stub_request(:get, custom_crm_url)
                        .with(
                          headers: {
                            "Authorization" => "Bearer custom-access-token",
                            "Content-Type" => "application/json"
                          }
                        )
                        .to_return(status: 200, body: JSON.generate(projectId: "my-custom-project"))
        default_crm_stub = stub_request(:get, default_crm_url)
        custom_sts_stub = stub_request(:post, custom_sts_url)
                          .to_return(
                            status: 200,
                            body: JSON.generate(
                              access_token: "custom-access-token",
                              issued_token_type: "urn:ietf:params:oauth:token-type:access_token",
                              token_type: "Bearer",
                              expires_in: 3600
                            )
                          )

        stub_subject_token
        creds = Google::Auth::ExternalAccount::Credentials.make_creds(
          json_key_io: StringIO.new(JSON.generate(cred_config))
        )
        expect(creds).to be_a(expected_class)

        client1 = Google::Auth::Credentials.new(creds)
        expect(creds.instance_variable_get(:@project_id)).to be_nil
        expect(client1.project_id).to eq("my-project-id")

        headers = {}
        creds.apply!(headers)
        expect(headers[:authorization]).to eq("Bearer custom-access-token")

        client2 = Google::Auth::Credentials.new(creds)

        expect(client2.project_id).to eq("my-custom-project")
        expect(unauth_crm_stub).to have_been_requested.once
        expect(custom_sts_stub).to have_been_requested.once
        expect(auth_crm_stub).to have_been_requested.once
        expect(default_crm_stub).not_to have_been_requested
        expect(a_request(:any, %r{googleapis\.com})).not_to have_been_made
      end
    end

    context "with AwsCredentials" do
      let(:expected_class) { Google::Auth::ExternalAccount::AwsCredentials }
      let(:cred_config) do
        {
          type: "external_account",
          audience: workload_audience,
          subject_token_type: "urn:ietf:params:aws:token-type:aws4_request",
          token_url: custom_sts_url,
          credential_source: {
            environment_id: "aws1",
            region_url: "http://169.254.169.254/latest/meta-data/placement/availability-zone",
            url: "http://169.254.169.254/latest/meta-data/iam/security-credentials",
            regional_cred_verification_url: "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"
          },
          universe_domain: custom_universe_domain
        }
      end

      def stub_subject_token
        env_vars = ENV.to_h.merge(
          Google::Auth::CredentialsLoader::AWS_REGION_VAR => "us-east-1",
          Google::Auth::CredentialsLoader::AWS_ACCESS_KEY_ID_VAR => "test-access-key",
          Google::Auth::CredentialsLoader::AWS_SECRET_ACCESS_KEY_VAR => "test-key-value"
        )
        env_vars.delete(Google::Auth::CredentialsLoader::AWS_SESSION_TOKEN_VAR)
        stub_const("ENV", env_vars)
      end

      include_examples "project_id resolution with custom universe_domain"
    end

    context "with IdentityPoolCredentials" do
      let(:expected_class) { Google::Auth::ExternalAccount::IdentityPoolCredentials }
      let(:cred_config) do
        {
          type: "external_account",
          audience: workload_audience,
          subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
          token_url: custom_sts_url,
          credential_source: {
            url: "https://idp.example.com/subject-token"
          },
          universe_domain: custom_universe_domain
        }
      end

      def stub_subject_token
        stub_request(:get, "https://idp.example.com/subject-token")
          .to_return(status: 200, body: "identity-pool-subject-token")
      end

      include_examples "project_id resolution with custom universe_domain"
    end

    context "with PluggableAuthCredentials" do
      let(:expected_class) { Google::Auth::ExternalAccount::PluggableAuthCredentials }
      let(:cred_config) do
        {
          type: "external_account",
          audience: workload_audience,
          subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
          token_url: custom_sts_url,
          credential_source: {
            executable: {
              command: "/fake/external/executable"
            }
          },
          universe_domain: custom_universe_domain
        }
      end

      def stub_subject_token
        stub_const("ENV", ENV.to_h.merge("GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES" => "1"))
        exe_response = JSON.generate(
          version: 1,
          success: true,
          token_type: "urn:ietf:params:oauth:token-type:jwt",
          id_token: "pluggable-subject-token",
          expiration_time: Time.now.to_i + 3600
        )
        status = double("Process::Status", exitstatus: 0, success?: true)
        allow(Open3).to receive(:capture3)
          .with(anything, "/fake/external/executable")
          .and_return([exe_response, "", status])
      end

      include_examples "project_id resolution with custom universe_domain"
    end
  end
end
