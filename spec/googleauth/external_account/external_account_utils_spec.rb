# Copyright 2026 Google LLC
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

require "spec_helper"
require "googleauth"

describe Google::Auth::ExternalAccount::ExternalAccountUtils do
  let(:dummy_class) do
    Class.new do
      include Google::Auth::Helpers::Connection
      include Google::Auth::ExternalAccount::ExternalAccountUtils
      attr_accessor :service_account_impersonation_url,
                    :audience,
                    :scope,
                    :access_token,
                    :workforce_pool_user_project
    end
  end
  let(:dummy_class_with_universe) do
    Class.new(dummy_class) do
      attr_accessor :universe_domain
    end
  end
  let(:instance) { dummy_class.new }
  let(:universe_instance) { dummy_class_with_universe.new }

  let(:workload_audience) do
    "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID"
  end
  let(:workforce_audience) do
    "//iam.googleapis.com/locations/global/workforcePools/POOL_ID/providers/PROVIDER_ID"
  end

  describe "constants" do
    it "retains public CLOUD_RESOURCE_MANAGER for backwards compatibility and exposes no new public constants" do
      expect(described_class::CLOUD_RESOURCE_MANAGER).to eq(
        "https://cloudresourcemanager.googleapis.com/v1/projects/"
      )
      expect(described_class.constants(false)).to contain_exactly(:CLOUD_RESOURCE_MANAGER)
    end
  end

  describe "#project_number" do
    it "extracts project number from a workload identity pool audience" do
      instance.audience = workload_audience
      expect(instance.project_number).to eq("123456")
    end

    it "returns nil for a workforce pool audience" do
      instance.audience = workforce_audience
      expect(instance.project_number).to be_nil
    end

    it "returns nil when 'projects' is the trailing segment" do
      instance.audience = "//iam.googleapis.com/projects"
      expect(instance.project_number).to be_nil
    end

    it "returns nil without raising when audience is nil" do
      instance.audience = nil
      expect(instance.project_number).to be_nil
    end
  end

  describe "#project_id" do
    let(:crm_headers) do
      {
        "Authorization" => "Bearer test-token",
        "Content-Type" => "application/json"
      }
    end

    before do
      universe_instance.audience = workload_audience
      universe_instance.scope = ["https://www.googleapis.com/auth/iam"]
      universe_instance.access_token = "test-token"
      universe_instance.universe_domain = "googleapis.com"
    end

    context "with default universe_domain" do
      it "requests Cloud Resource Manager on googleapis.com and parses projectId" do
        stub = stub_request(:get, "https://cloudresourcemanager.googleapis.com/v1/projects/123456")
               .with(headers: crm_headers)
               .to_return(status: 200, body: JSON.generate(projectId: "my-default-project"))

        expect(universe_instance.project_id).to eq("my-default-project")
        expect(stub).to have_been_requested.once
      end

      it "defaults nil universe_domain to googleapis.com" do
        universe_instance.universe_domain = nil
        stub = stub_request(:get, "https://cloudresourcemanager.googleapis.com/v1/projects/123456")
               .with(headers: crm_headers)
               .to_return(status: 200, body: JSON.generate(projectId: "nil-universe-project"))

        expect(universe_instance.project_id).to eq("nil-universe-project")
        expect(stub).to have_been_requested.once
      end

      it "defaults a standalone mixin without #universe_domain to googleapis.com" do
        instance.audience = workload_audience
        instance.scope = ["https://www.googleapis.com/auth/iam"]
        instance.access_token = "test-token"
        stub = stub_request(:get, "https://cloudresourcemanager.googleapis.com/v1/projects/123456")
               .with(headers: crm_headers)
               .to_return(status: 200, body: JSON.generate(projectId: "standalone-project"))

        expect(instance.project_id).to eq("standalone-project")
        expect(stub).to have_been_requested.once
      end

      it "memoizes project_id after an HTTP 200 response" do
        stub = stub_request(:get, "https://cloudresourcemanager.googleapis.com/v1/projects/123456")
               .with(headers: crm_headers)
               .to_return(status: 200, body: JSON.generate(projectId: "memoized-project"))

        expect(universe_instance.project_id).to eq("memoized-project")
        expect(universe_instance.project_id).to eq("memoized-project")
        expect(stub).to have_been_requested.once
      end

      [401, 403, 500].each do |error_status|
        it "does not memoize project_id on HTTP #{error_status} and retries on subsequent call" do
          stub = stub_request(:get, "https://cloudresourcemanager.googleapis.com/v1/projects/123456")
                 .with(headers: crm_headers)
                 .to_return(
                   { status: error_status, body: "" },
                   { status: 200, body: JSON.generate(projectId: "recovered-project") }
                 )

          expect(universe_instance.project_id).to be_nil
          expect(universe_instance.project_id).to eq("recovered-project")
          expect(stub).to have_been_requested.twice
        end
      end

      it "skips HTTP request when both project_number and workforce_pool_user_project are nil" do
        universe_instance.audience = workforce_audience
        universe_instance.workforce_pool_user_project = nil

        expect(universe_instance.project_id).to be_nil
        expect(a_request(:any, %r{cloudresourcemanager})).not_to have_been_made
      end

      it "skips HTTP request when scope is nil" do
        universe_instance.scope = nil

        expect(universe_instance.project_id).to be_nil
        expect(a_request(:any, %r{cloudresourcemanager})).not_to have_been_made
      end
    end

    context "with custom universe_domain" do
      ["myuniverse.com", "universe-domain.example.com"].each do |custom_domain|
        it "routes workload project_number lookup to cloudresourcemanager.#{custom_domain} instead of googleapis.com" do
          universe_instance.universe_domain = custom_domain
          custom_stub = stub_request(:get, "https://cloudresourcemanager.#{custom_domain}/v1/projects/123456")
                        .with(headers: crm_headers)
                        .to_return(status: 200, body: JSON.generate(projectId: "custom-workload-project"))
          default_stub = stub_request(:get, "https://cloudresourcemanager.googleapis.com/v1/projects/123456")

          expect(universe_instance.project_id).to eq("custom-workload-project")
          expect(custom_stub).to have_been_requested.once
          expect(default_stub).not_to have_been_requested
        end

        it "routes workforce_pool_user_project lookup to cloudresourcemanager.#{custom_domain} instead of googleapis.com" do
          universe_instance.universe_domain = custom_domain
          universe_instance.audience = workforce_audience
          universe_instance.workforce_pool_user_project = "789012"
          custom_stub = stub_request(:get, "https://cloudresourcemanager.#{custom_domain}/v1/projects/789012")
                        .with(headers: crm_headers)
                        .to_return(status: 200, body: JSON.generate(projectId: "custom-workforce-project"))
          default_stub = stub_request(:get, "https://cloudresourcemanager.googleapis.com/v1/projects/789012")

          expect(universe_instance.project_id).to eq("custom-workforce-project")
          expect(custom_stub).to have_been_requested.once
          expect(default_stub).not_to have_been_requested
        end
      end
    end
  end

  describe "#service_account_email" do
    context "when impersonation URL is present" do
      it "extracts the email correctly without a trailing colon" do
        instance.service_account_impersonation_url =
          "https://us-east1-iamcredentials.googleapis.com/v1/projects/-/" \
          "serviceAccounts/service-1234@project-name.iam.gserviceaccount.com:generateAccessToken"
        expect(instance.service_account_email).to eq("service-1234@project-name.iam.gserviceaccount.com")
      end
    end

    context "when impersonation URL is nil" do
      it "returns nil" do
        instance.service_account_impersonation_url = nil
        expect(instance.service_account_email).to be_nil
      end
    end

    context "when impersonation URL format is invalid" do
      it "returns nil" do
        instance.service_account_impersonation_url = "https://invalid/format/url"
        expect(instance.service_account_email).to be_nil
      end
    end
  end
end
