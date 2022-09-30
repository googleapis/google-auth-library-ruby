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

require "googleauth"
require "googleauth/external_account/aws_credentials"
require "spec_helper"

include Google::Auth::CredentialsLoader

describe Google::Auth::ExternalAccount::AwsCredentials do
  AwsCredentials = Google::Auth::ExternalAccount::AwsCredentials

    after :example do
      ENV[AWS_DEFAULT_REGION_VAR] = nil
    end

  let(:aws_region) { "us-east-1c" }

  describe "when a region url is provided" do

    let :aws_credential_params do
      {
        token_url: "https://sts.amazonaws.com",
        credential_source: {
          "region_url" => "http://169.254.169.254/latest/meta-data/placement/availability-zone"
        }
      }
    end

    let :credentials do
      AwsCredentials.new(aws_credential_params)
    end

    it "does not raise an error" do
    stub_request(:get, aws_credential_params.dig(:credential_source, "region_url"))
      .to_return(status: 200, body: aws_region, headers: {"Content-Type" => "text/plain"})

      expect { credentials }.to_not raise_error
    end
  end

  describe "when a region is provided as an environment variable" do
    let(:aws_region) { "us-east-1c" }

    let :aws_credential_params do
      {
        token_url: "https://sts.amazonaws.com",
      }
    end

    let :credentials do
      AwsCredentials.new(aws_credential_params)
    end

    it "does not raise an error" do
      ENV[AWS_DEFAULT_REGION_VAR] = aws_region
      expect { credentials }.to_not raise_error
    end
  end

  describe "when a region is not provided" do
    let :aws_credential_params do
      {
        token_url: "https://sts.amazonaws.com",
      }
    end

    let :credentials do
      AwsCredentials.new(aws_credential_params)
    end

    it "raises an error" do
      expect { credentials }.to raise_error(/region_url or region must be set for external account credentials/)
    end
  end
end
