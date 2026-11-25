# Copyright 2024 Google, Inc.
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

require "googleauth/impersonated_service_account"
require_relative "../spec_helper"

describe Google::Auth::ImpersonatedServiceAccountCredentials do
 
  describe ".make_creds with json_key_io" do
    let(:key) { OpenSSL::PKey::RSA.new 2048 }

    let(:authorized_user_json) do
      {
        "type": "authorized_user",
        "client_id": "client_id",
        "client_secret": "client_secret",
        "refresh_token": "refresh_token"
      }
    end

    let(:service_account_json) do
      {
        "type": "service_account",
        "private_key": key.to_pem,
        "client_email": "client_email",
        "scope": "https://www.googleapis.com/auth/iam"
      }
    end

    let(:impersonated_json) do
      {
        "type": "impersonated_service_account",
        "service_account_impersonation_url": impersonation_url,
        "scopes": ["scope1"],
        "source_credentials": source_credentials_json
      }
    end

    context "with authorized_user source credentials" do
      let(:source_credentials_json) { authorized_user_json }

      it "creates credentials with UserRefreshCredentials as source" do
        creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          json_key_io: StringIO.new(JSON.generate(impersonated_json))
        )

        expect(creds).to be_a(Google::Auth::ImpersonatedServiceAccountCredentials)
        expect(creds.source_credentials).to be_a(Google::Auth::UserRefreshCredentials)
        expect(creds.impersonation_url).to eq(impersonation_url)
        expect(creds.scope).to eq(["scope1"])
      end
    end

    context "with service_account source credentials" do
      let(:source_credentials_json) { service_account_json }

      it "creates credentials with ServiceAccountCredentials as source" do
        creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          json_key_io: StringIO.new(JSON.generate(impersonated_json))
        )

        expect(creds).to be_a(Google::Auth::ImpersonatedServiceAccountCredentials)
        expect(creds.source_credentials).to be_a(Google::Auth::ServiceAccountCredentials)
        expect(creds.source_credentials.scope).to eq(Google::Auth::ImpersonatedServiceAccountCredentials::IAM_SCOPE)
        expect(creds.impersonation_url).to eq(impersonation_url)
        expect(creds.scope).to eq(["scope1"])
      end

      it "sends source authorization header during apply! in default universe" do
        creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          json_key_io: StringIO.new(JSON.generate(impersonated_json))
        )

        token_stub = stub_request(:post, Google::Auth::ServiceAccountCredentials::TOKEN_CRED_URI)
          .to_return(
            body: JSON.generate({ "access_token" => "sa_source_token", "token_type" => "Bearer", "expires_in" => 3600 }),
            status: 200,
            headers: { "Content-Type" => "application/json" }
          )
        impersonation_stub = stub_request(:post, impersonation_url)
          .with(headers: { "Authorization" => "Bearer sa_source_token" })
          .to_return(
            body: JSON.generate({ "accessToken" => "impersonated_token", "expireTime" => (Time.now.utc + 3600).to_s }),
            status: 200,
            headers: { "Content-Type" => "application/json" }
          )

        headers = {}
        creds.apply!(headers)

        expect(token_stub).to have_been_requested.once
        expect(impersonation_stub).to have_been_requested.once
        expect(headers[:authorization]).to eq("Bearer impersonated_token")
      end

      it "sends a self-signed JWT authorization header during apply! in a non-default universe" do
        non_gdu_sa_json = service_account_json.merge("universe_domain": "myuniverse.com")
        json = impersonated_json.merge("source_credentials": non_gdu_sa_json)
        creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          json_key_io: StringIO.new(JSON.generate(json))
        )

        impersonation_stub = stub_request(:post, impersonation_url)
          .with(headers: { "Authorization" => /\ABearer [^.]+\.[^.]+\.[^.]+\z/ })
          .to_return(
            body: JSON.generate({ "accessToken" => "impersonated_token", "expireTime" => (Time.now.utc + 3600).to_s }),
            status: 200,
            headers: { "Content-Type" => "application/json" }
          )

        headers = {}
        creds.apply!(headers)

        expect(impersonation_stub).to have_been_requested.once
        expect(headers[:authorization]).to eq("Bearer impersonated_token")
      end
    end

    context "with recursive impersonated_service_account source credentials" do
      let(:recursive_impersonated_json) do
        {
          "type": "impersonated_service_account",
          "service_account_impersonation_url": impersonation_url,
          "scopes": ["scope1"],
          "source_credentials": {
            "type": "impersonated_service_account"
          }
        }
      end

      it "raises a runtime error" do
        expect {
          Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
            json_key_io: StringIO.new(JSON.generate(recursive_impersonated_json))
          )
        }.to raise_error(Google::Auth::InitializationError, /Source credentials can't be of type.*use delegates/)
      end
    end

    context "scope handling" do
      let(:source_credentials_json) { authorized_user_json }

      it "uses scope from JSON if not provided in options" do
        creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          json_key_io: StringIO.new(JSON.generate(impersonated_json))
        )
        expect(creds.scope).to eq(["scope1"])
      end

      it "uses scope from options if provided" do
        creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          json_key_io: StringIO.new(JSON.generate(impersonated_json)),
          scope: ["scope2"]
        )
        expect(creds.scope).to eq(["scope2"])
      end
    end

    context "universe_domain handling" do
      let(:external_account_identity_pool_json) do
        {
          "type": "external_account",
          "audience": "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID",
          "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
          "token_url": "https://sts.myuniverse.com/v1/token",
          "credential_source": {
            "url": "https://idp.example.com/subject-token"
          }
        }
      end

      let(:external_account_aws_json) do
        {
          "type": "external_account",
          "audience": "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID",
          "subject_token_type": "urn:ietf:params:aws:token-type:aws4_request",
          "token_url": "https://sts.myuniverse.com/v1/token",
          "credential_source": {
            "environment_id": "aws1",
            "regional_cred_verification_url": "https://sts.{region}.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15"
          }
        }
      end

      let(:external_account_pluggable_json) do
        {
          "type": "external_account",
          "audience": "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID",
          "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
          "token_url": "https://sts.myuniverse.com/v1/token",
          "credential_source": {
            "executable": {
              "command": "/fake/external/executable"
            }
          }
        }
      end

      let(:source_credentials_json) { external_account_identity_pool_json }

      it "defaults to googleapis.com when universe_domain is omitted everywhere" do
        creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          json_key_io: StringIO.new(JSON.generate(impersonated_json))
        )
        expect(creds.universe_domain).to eq("googleapis.com")
        expect(creds.source_credentials.universe_domain).to eq("googleapis.com")
      end

      it "propagates top-level universe_domain to external_account IdentityPoolCredentials" do
        json = impersonated_json.merge("universe_domain": "myuniverse.com")
        creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          json_key_io: StringIO.new(JSON.generate(json))
        )
        expect(creds.universe_domain).to eq("myuniverse.com")
        expect(creds.source_credentials.universe_domain).to eq("myuniverse.com")
        expect(creds.duplicate.universe_domain).to eq("myuniverse.com")
      end

      it "propagates top-level universe_domain to external_account AwsCredentials" do
        json = impersonated_json.merge(
          "universe_domain": "myuniverse.com",
          "source_credentials": external_account_aws_json
        )
        creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          json_key_io: StringIO.new(JSON.generate(json))
        )
        expect(creds.source_credentials).to be_a(Google::Auth::ExternalAccount::AwsCredentials)
        expect(creds.universe_domain).to eq("myuniverse.com")
        expect(creds.source_credentials.universe_domain).to eq("myuniverse.com")
      end

      it "propagates top-level universe_domain to external_account PluggableAuthCredentials" do
        json = impersonated_json.merge(
          "universe_domain": "myuniverse.com",
          "source_credentials": external_account_pluggable_json
        )
        creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          json_key_io: StringIO.new(JSON.generate(json))
        )
        expect(creds.source_credentials).to be_a(Google::Auth::ExternalAccount::PluggableAuthCredentials)
        expect(creds.universe_domain).to eq("myuniverse.com")
        expect(creds.source_credentials.universe_domain).to eq("myuniverse.com")
      end

      it "propagates top-level universe_domain to service_account source credentials" do
        json = impersonated_json.merge(
          "universe_domain": "myuniverse.com",
          "source_credentials": service_account_json
        )
        creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          json_key_io: StringIO.new(JSON.generate(json))
        )
        expect(creds.source_credentials).to be_a(Google::Auth::ServiceAccountCredentials)
        expect(creds.universe_domain).to eq("myuniverse.com")
        expect(creds.source_credentials.universe_domain).to eq("myuniverse.com")
      end

      it "inherits source_credentials universe_domain when top-level universe_domain is omitted" do
        json = impersonated_json.merge(
          "source_credentials": external_account_identity_pool_json.merge("universe_domain": "myuniverse.com")
        )
        creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          json_key_io: StringIO.new(JSON.generate(json))
        )
        expect(creds.universe_domain).to eq("myuniverse.com")
      end

      it "inherits source_credentials universe_domain when top-level universe_domain is nil" do
        json = impersonated_json.merge(
          "universe_domain": nil,
          "source_credentials": external_account_identity_pool_json.merge("universe_domain": "myuniverse.com")
        )
        creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          json_key_io: StringIO.new(JSON.generate(json))
        )
        expect(creds.universe_domain).to eq("myuniverse.com")
      end

      it "succeeds when top-level and source_credentials universe_domain match" do
        json = impersonated_json.merge(
          "universe_domain": "myuniverse.com",
          "source_credentials": external_account_identity_pool_json.merge("universe_domain": "myuniverse.com")
        )
        creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          json_key_io: StringIO.new(JSON.generate(json))
        )
        expect(creds.universe_domain).to eq("myuniverse.com")
      end

      it "raises InitializationError when top-level and source_credentials universe_domain conflict" do
        json = impersonated_json.merge(
          "universe_domain": "myuniverse.com",
          "source_credentials": external_account_identity_pool_json.merge("universe_domain": "googleapis.com")
        )
        expect do
          Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
            json_key_io: StringIO.new(JSON.generate(json))
          )
        end.to raise_error(Google::Auth::InitializationError, /does not match/)

        reverse_json = impersonated_json.merge(
          "universe_domain": "googleapis.com",
          "source_credentials": external_account_identity_pool_json.merge("universe_domain": "myuniverse.com")
        )
        expect do
          Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
            json_key_io: StringIO.new(JSON.generate(reverse_json))
          )
        end.to raise_error(Google::Auth::InitializationError, /does not match/)
      end

      it "raises InitializationError when top-level universe_domain is empty or non-string" do
        ["", false, 123].each do |invalid_domain|
          json = impersonated_json.merge("universe_domain": invalid_domain)
          expect do
            Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
              json_key_io: StringIO.new(JSON.generate(json))
            )
          end.to raise_error(Google::Auth::InitializationError, /Invalid universe_domain/)
        end
      end

      it "preserves top-level universe_domain when loaded via DefaultCredentials.make_creds" do
        require "googleauth/default_credentials"
        json = impersonated_json.merge("universe_domain": "myuniverse.com")
        creds = Google::Auth::DefaultCredentials.make_creds(
          json_key_io: StringIO.new(JSON.generate(json))
        )
        expect(creds).to be_a(Google::Auth::ImpersonatedServiceAccountCredentials)
        expect(creds.universe_domain).to eq("myuniverse.com")
        expect(creds.source_credentials.universe_domain).to eq("myuniverse.com")
      end
    end
  end
 
  let(:impersonation_url) {"https://iamcredentials.example.com/v1/projects/-/serviceAccounts/test:generateAccessToken"}

  def make_auth_stubs opts
    body_fields = { "token_type" => "Bearer", "expires_in" => 3600 }
    body_fields["accessToken"] = opts[:access_token]
    body_fields["expireTime"] = opts[:expireTime]
    body = JSON.generate body_fields
    stub_request(:post, impersonation_url)
      .with(headers: { "Authorization" => "Bearer source_token" })
      .to_return(body:    body,
                 status:  opts[:status] || 200,
                 headers: { "Content-Type" => "application/json" })
  end

  def make_error_stub(status, body = "error message")
    stub_request(:post, impersonation_url)
      .with(headers: { "Authorization" => "Bearer source_token" })
      .to_return(
        body: body,
        status: status,
        headers: { "Content-Type" => "application/json" }
      )
  end

  before :example do
    @base_creds = double("Credentials")
    @source_creds = double("Credentials")
    allow(@base_creds).to receive(:duplicate).and_return(@source_creds)
    allow(@source_creds).to receive(:updater_proc).and_return(
      proc { |hash, opts = {}| hash.clone.tap { |h| h[:authorization] = "Bearer source_token" } }
    )
  end

  describe "#initialize" do
    it "raises ArgumentError when both base_credentials and source_credentials are missing" do
      expect {
        Google::Auth::ImpersonatedServiceAccountCredentials.make_creds({
          impersonation_url: impersonation_url,
          scope: ["scope1", "scope2"]
        })
      }.to raise_error(ArgumentError, "Missing required option: either :base_credentials or :source_credentials")
    end

    it "raises ArgumentError when impersonation_url is missing" do
      expect {
        Google::Auth::ImpersonatedServiceAccountCredentials.make_creds({
          base_credentials: @base_creds,
          scope: ["scope1", "scope2"]
        })
      }.to raise_error(ArgumentError, "Missing required option: :impersonation_url")
    end

    it "raises ArgumentError when scope is missing" do
      expect {
        Google::Auth::ImpersonatedServiceAccountCredentials.make_creds({
          base_credentials: @base_creds,
          impersonation_url: impersonation_url
        })
      }.to raise_error(ArgumentError, "Missing required option: :scope")
    end

    it "does not raise error when source_credentials is provided without base_credentials" do
      expect {
        Google::Auth::ImpersonatedServiceAccountCredentials.make_creds({
          source_credentials: @source_creds,
          impersonation_url: impersonation_url,
          scope: ["scope1", "scope2"]
        })
      }.not_to raise_error
    end

    it "should call duplicate when available" do

      creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds({
        base_credentials: @base_creds,
        impersonation_url: impersonation_url,
        scope: ["scope1", "scope2"]
      })
      expect(@base_creds).to have_received(:duplicate)
      expect(creds.base_credentials).to eq(@base_creds)
      expect(creds.source_credentials).to eq(@source_creds)
    end

    it "should use base creds if they don't duplicate" do
      creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds({
        base_credentials: @base_creds,
        impersonation_url: impersonation_url,
        scope: ["scope1", "scope2"]
      })
      expect(creds.base_credentials).to eq(@base_creds)
    end
  end

  describe "#apply" do
    before :each do
      @stub = make_auth_stubs(access_token: "1/abcde", expireTime: (Time.now.utc + 3600).to_s)
    end

    it "should call apply! of the base credentials" do
      creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds({
        base_credentials: @base_creds,
        impersonation_url: impersonation_url,
        scope: ["scope1", "scope2"]
      })

      creds.apply!({})

      expect(@source_creds).to have_received(:updater_proc)
    end

    it "should post to impersonation url" do
      creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds({
        base_credentials: @base_creds,
        impersonation_url: impersonation_url,
        scope: ["scope1", "scope2"]
      })

      headers = {}
      creds.apply!(headers)
      
      expect(@stub).to have_been_requested.once
      expect(headers[Google::Auth::ImpersonatedServiceAccountCredentials::AUTH_METADATA_KEY]).to eq("Bearer 1/abcde")
    end

    it "should update internal state" do
      creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds({
        base_credentials: @base_creds,
        impersonation_url: impersonation_url,
        scope: ["scope1", "scope2"]
      })

      creds.apply!({})
      
      expect(creds.access_token).to eq("1/abcde")
      expect(creds.expires_within? 3600).to be true
    end

    it "should correctly apply auth headers when source is a real UserRefreshCredentials" do
      source_creds = Google::Auth::UserRefreshCredentials.new(
        client_id: "client_id",
        client_secret: "client_secret",
        refresh_token: "refresh_token"
      )
      source_creds.access_token = "source_user_token"

      creds = Google::Auth::ImpersonatedServiceAccountCredentials.new(
        source_credentials: source_creds,
        impersonation_url: impersonation_url,
        scope: ["scope1"]
      )

      token_stub = stub_request(:post, impersonation_url)
        .with(headers: { "Authorization" => "Bearer source_user_token" })
        .to_return(
          body: JSON.generate({ "accessToken" => "impersonated_token", "expireTime" => (Time.now.utc + 3600).to_s }),
          status: 200,
          headers: { "Content-Type" => "application/json" }
        )

      headers = {}
      creds.apply!(headers)

      expect(token_stub).to have_been_requested.once
      expect(headers[:authorization]).to eq("Bearer impersonated_token")
    end

    describe "duplicates" do
      before :example do
        @initial_creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          base_credentials: @base_creds,
          impersonation_url: "test-impersonation-url",
          scope: ["https://www.googleapis.com/auth/cloud-platform"]
        )
        @dup_creds = @initial_creds.duplicate
      end
  
      it "should duplicate the scope" do
        expect(@dup_creds.scope).to eq ["https://www.googleapis.com/auth/cloud-platform"]
        expect(@dup_creds.duplicate(scope: ["https://www.googleapis.com/auth/devstorage.read_only"]).scope).to eq ["https://www.googleapis.com/auth/devstorage.read_only"]
      end
  
      it "should duplicate the base_credentials" do
        expect(@dup_creds.base_credentials).to eq @base_creds
        expect(@dup_creds.duplicate(base_credentials: :bar).base_credentials).to eq :bar
      end
  
      it "should duplicate the source credentials" do
        expect(@dup_creds.source_credentials).to eq @source_creds
        expect(@dup_creds.duplicate(source_credentials: :bar).source_credentials).to eq :bar
      end
  
      it "should duplicate the impersonation_url" do
        expect(@dup_creds.impersonation_url).to eq "test-impersonation-url"
        expect(@dup_creds.duplicate(impersonation_url: "test-impersonation-url-2").impersonation_url).to eq "test-impersonation-url-2"
      end
    end
  end

  describe "error handling" do
    describe "normalize_timestamp" do
      it "raises CredentialsError with detailed information for invalid time value" do
        creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          base_credentials: @base_creds,
          impersonation_url: impersonation_url,
          scope: ["https://www.googleapis.com/auth/cloud-platform"]
        )
        
        # Allow the principal method to be called on our mock source_creds
        allow(@source_creds).to receive(:principal).and_return("test-principal")
        
        expect { creds.send(:normalize_timestamp, 12345) }.to raise_error do |error|
          expect(error).to be_a(Google::Auth::CredentialsError)
          expect(error.message).to match(/Invalid time value 12345/)
          expect(error.credential_type_name).to eq("Google::Auth::ImpersonatedServiceAccountCredentials")
          expect(error.principal).to eq("test-principal")
        end
      end
    end
    let(:creds) do
      Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
        base_credentials: @base_creds,
        impersonation_url: impersonation_url,
        scope: ["https://www.googleapis.com/auth/cloud-platform"]
      )
    end

    # Allow the principal method to be called on our mock source_creds
    before do
      allow(@source_creds).to receive(:principal).and_return("test-principal")
    end

    context "when response status is 403" do
      it "raises UnexpectedStatusError with detailed information" do
        stub = make_error_stub(403, "Permission denied")
        
        expect { creds.apply!({}) }.to raise_error do |error|
          expect(error).to be_a(Google::Auth::UnexpectedStatusError)
          expect(error.message).to match(/Unexpected error code 403.\n Permission denied/)
          expect(error.credential_type_name).to eq("Google::Auth::ImpersonatedServiceAccountCredentials")
          expect(error.principal).to eq("test-principal")
        end
        
        expect(stub).to have_been_requested.once
      end
    end

    context "when response status is 500" do
      it "raises UnexpectedStatusError with detailed information" do
        stub = make_error_stub(500, "Internal server error")
        
        expect { creds.apply!({}) }.to raise_error do |error|
          expect(error).to be_a(Google::Auth::UnexpectedStatusError)
          expect(error.message).to match(/Unexpected error code 500.\n Internal server error/)
          expect(error.credential_type_name).to eq("Google::Auth::ImpersonatedServiceAccountCredentials")
          expect(error.principal).to eq("test-principal")
        end
        
        expect(stub).to have_been_requested.once
      end
    end

    context "when response status is other error code (e.g. 401)" do
      it "raises AuthorizationError with detailed information" do
        stub = make_error_stub(401, "Unauthorized")
        
        expect { creds.apply!({}) }.to raise_error do |error|
          expect(error).to be_a(Google::Auth::AuthorizationError)
          expect(error.message).to match(/Unexpected error code 401.\n Unauthorized/)
          expect(error.credential_type_name).to eq("Google::Auth::ImpersonatedServiceAccountCredentials")
          expect(error.principal).to eq("test-principal")
        end
        
        expect(stub).to have_been_requested.once
      end
    end
  end
end
