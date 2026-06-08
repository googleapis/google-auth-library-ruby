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
      include Google::Auth::ExternalAccount::ExternalAccountUtils
      attr_accessor :service_account_impersonation_url
    end
  end
  let(:instance) { dummy_class.new }

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
