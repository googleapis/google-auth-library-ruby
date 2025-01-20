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
 
  let(:impersonation_url) {"https://iamcredentials.example.com/v1/projects/-/serviceAccounts/test:generateAccessToken"}

  def make_auth_stubs opts
    body_fields = { "token_type" => "Bearer", "expires_in" => 3600 }
    body_fields["accessToken"] = opts[:access_token]
    body_fields["expireTime"] = opts[:expireTime]
    body = MultiJson.dump body_fields
    stub_request(:post, impersonation_url)
      .to_return(body:    body,
                   status:  200,
                   headers: { "Content-Type" => "application/json" })
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
end
