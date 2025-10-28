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
        "private_key": "-----BEGIN PRIVATE KEY-----\nprivate_key\n-----END PRIVATE KEY-----\n",
        "client_email": "client_email"
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
          json_key_io: StringIO.new(MultiJson.dump(impersonated_json))
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
          json_key_io: StringIO.new(MultiJson.dump(impersonated_json))
        )

        expect(creds).to be_a(Google::Auth::ImpersonatedServiceAccountCredentials)
        expect(creds.source_credentials).to be_a(Google::Auth::ServiceAccountCredentials)
        expect(creds.impersonation_url).to eq(impersonation_url)
        expect(creds.scope).to eq(["scope1"])
      end
    end

    context "with recursive impersonated_service_account source credentials" do
      let(:source_credentials_json) { impersonated_json }

      it "raises a runtime error" do
        expect {
          Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
            json_key_io: StringIO.new(MultiJson.dump(impersonated_json))
          )
        }.to raise_error(RuntimeError, "Source credentials can't be of type impersonated_service_account")
      end
    end

    context "scope handling" do
      let(:source_credentials_json) { authorized_user_json }

      it "uses scope from JSON if not provided in options" do
        creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          json_key_io: StringIO.new(MultiJson.dump(impersonated_json))
        )
        expect(creds.scope).to eq(["scope1"])
      end

      it "uses scope from options if provided" do
        creds = Google::Auth::ImpersonatedServiceAccountCredentials.make_creds(
          json_key_io: StringIO.new(MultiJson.dump(impersonated_json)),
          scope: ["scope2"]
        )
        expect(creds.scope).to eq(["scope2"])
      end
    end
  end
 
  let(:impersonation_url) {"https://iamcredentials.example.com/v1/projects/-/serviceAccounts/test:generateAccessToken"}

  def make_auth_stubs opts
    body_fields = { "token_type" => "Bearer", "expires_in" => 3600 }
    body_fields["accessToken"] = opts[:access_token]
    body_fields["expireTime"] = opts[:expireTime]
    body = MultiJson.dump body_fields
    stub_request(:post, impersonation_url)
      .to_return(body:    body,
                   status:  opts[:status] || 200,
                   headers: { "Content-Type" => "application/json" })
  end

  def make_error_stub(status, body = "error message")
    stub_request(:post, impersonation_url)
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
    allow(@source_creds).to receive(:updater_proc).and_return(Proc.new { |hash| {} })
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

      hash = {}
      creds.apply!(hash)
      
      expect(@stub).to have_been_requested
      expect(hash[Google::Auth::ImpersonatedServiceAccountCredentials::AUTH_METADATA_KEY]).to eq("Bearer 1/abcde")
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
        
        expect(stub).to have_been_requested
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
        
        expect(stub).to have_been_requested
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
        
        expect(stub).to have_been_requested
      end
    end
  end
end
