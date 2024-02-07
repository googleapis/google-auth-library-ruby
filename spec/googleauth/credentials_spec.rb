# Copyright 2015 Google, Inc.
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

require "googleauth"


# This test is testing the private class Google::Auth::Credentials. We want to
# make sure that the passed in scope propogates to the Signet object. This means
# testing the private API, which is generally frowned on.
describe Google::Auth::Credentials, :private do
  let(:token) { "1/abcdef1234567890" }
  let :default_keyfile_hash do
    {
      "type"             => "service_account",
      "private_key_id"   => "testabc1234567890xyz",
      "private_key"      => "-----BEGIN RSA PRIVATE KEY-----\nMIIBOwIBAAJBAOyi0Hy1l4Ym2m2o71Q0TF4O9E81isZEsX0bb+Bqz1SXEaSxLiXM\nUZE8wu0eEXivXuZg6QVCW/5l+f2+9UPrdNUCAwEAAQJAJkqubA/Chj3RSL92guy3\nktzeodarLyw8gF8pOmpuRGSiEo/OLTeRUMKKD1/kX4f9sxf3qDhB4e7dulXR1co/\nIQIhAPx8kMW4XTTL6lJYd2K5GrH8uBMp8qL5ya3/XHrBgw3dAiEA7+3Iw3ULTn2I\n1J34WlJ2D5fbzMzB4FAHUNEV7Ys3f1kCIQDtUahCMChrl7+H5t9QS+xrn77lRGhs\nB50pjvy95WXpgQIhAI2joW6JzTfz8fAapb+kiJ/h9Vcs1ZN3iyoRlNFb61JZAiA8\nNy5NyNrMVwtB/lfJf1dAK/p/Bwd8LZLtgM6PapRfgw==\n-----END RSA PRIVATE KEY-----\n",
      "client_email"     => "credz-testabc1234567890xyz@developer.gserviceaccount.com",
      "client_id"        => "credz-testabc1234567890xyz.apps.googleusercontent.com",
      "type"             => "service_account",
      "project_id"       => "a_project_id",
      "quota_project_id" => "b_project_id"
    }
  end
  let(:default_keyfile_content) { JSON.generate default_keyfile_hash }

  def stub_token_request access_token: nil, id_token: nil, uri: nil
    body_fields = { "token_type" => "Bearer", "expires_in" => 3600 }
    if id_token
      body_fields["id_token"] = id_token
    else
      body_fields["access_token"] = access_token || "12345abcde"
    end
    body = MultiJson.dump body_fields
    uri ||= "https://oauth2.googleapis.com/token"
    stub_request(:post, uri)
      .to_return(body: body, status: 200, headers: { "Content-Type" => "application/json" })
  end

  def stub_metadata_request
    stub_request(:get, "http://169.254.169.254/")
      .to_return(status: 404)
  end

  it "uses a default scope" do
    creds = Google::Auth::Credentials.new default_keyfile_hash
    client = creds.client
    expect(client.token_credential_uri.to_s).to eq("https://oauth2.googleapis.com/token")
    expect(client.audience).to eq("https://oauth2.googleapis.com/token")
    expect(client.scope).to be_nil
    expect(client.issuer).to eq(default_keyfile_hash["client_email"])
    expect(client.signing_key).to be_a_kind_of(OpenSSL::PKey::RSA)
  end

  it "uses a custom scope" do
    stub_token_request
    creds = Google::Auth::Credentials.new default_keyfile_hash, scope: "http://example.com/scope"
    client = creds.client
    expect(client.token_credential_uri.to_s).to eq("https://oauth2.googleapis.com/token")
    expect(client.audience).to eq("https://oauth2.googleapis.com/token")
    expect(client.scope).to eq(["http://example.com/scope"])
    expect(client.issuer).to eq(default_keyfile_hash["client_email"])
    expect(client.signing_key).to be_a_kind_of(OpenSSL::PKey::RSA)
  end

  it "uses empty paths and env_vars by default" do
    expect(Google::Auth::Credentials.paths).to eq([])
    expect(Google::Auth::Credentials.env_vars).to eq([])
  end

  describe "subclasses using CONSTANTS" do
    it "passes in other env paths" do
      test_path_env_val = "/unknown/path/to/file.txt".freeze
      test_json_env_val = JSON.generate default_keyfile_hash

      ENV["TEST_PATH"] = test_path_env_val
      ENV["TEST_JSON_VARS"] = test_json_env_val

      class TestCredentials1 < Google::Auth::Credentials
        TOKEN_CREDENTIAL_URI = "https://example.com/token".freeze
        AUDIENCE = "https://example.com/audience".freeze
        SCOPE = "http://example.com/scope".freeze
        PATH_ENV_VARS = ["TEST_PATH"].freeze
        JSON_ENV_VARS = ["TEST_JSON_VARS"].freeze
      end

      allow(::File).to receive(:file?).with(test_path_env_val) { false }
      allow(::File).to receive(:file?).with(test_json_env_val) { false }

      creds = TestCredentials1.default enable_self_signed_jwt: true
      expect(creds).to be_a_kind_of(TestCredentials1)
      expect(creds.project_id).to eq(default_keyfile_hash["project_id"])
      expect(creds.quota_project_id).to eq(default_keyfile_hash["quota_project_id"])

      client = creds.client
      expect(client).to be_a_kind_of(Google::Auth::ServiceAccountCredentials)
      expect(client.token_credential_uri.to_s).to eq("https://example.com/token")
      expect(client.audience).to eq("https://example.com/audience")
      expect(client.scope).to eq(["http://example.com/scope"])
      expect(client.instance_variable_get(:@enable_self_signed_jwt)).to eq(true)
      expect(client.target_audience).to be_nil
      expect(client.issuer).to eq(default_keyfile_hash["client_email"])
    end

    it "can use PATH_ENV_VARS to get keyfile path" do
      class TestCredentials2 < Google::Auth::Credentials
        SCOPE = "http://example.com/scope".freeze
        PATH_ENV_VARS = %w[PATH_ENV_DUMMY PATH_ENV_TEST].freeze
        JSON_ENV_VARS = ["JSON_ENV_DUMMY"].freeze
        DEFAULT_PATHS = ["~/default/path/to/file.txt"].freeze
      end

      allow(::ENV).to receive(:[]).with("PATH_ENV_DUMMY") { "/fake/path/to/file.txt" }
      allow(::File).to receive(:file?).with("/fake/path/to/file.txt") { false }
      allow(::ENV).to receive(:[]).with("PATH_ENV_TEST") { "/unknown/path/to/file.txt" }
      allow(::ENV).to receive(:[]).with("https_proxy") { nil }
      allow(::ENV).to receive(:[]).with("HTTPS_PROXY") { nil }
      allow(::File).to receive(:file?).with("/unknown/path/to/file.txt") { true }
      allow(::File).to receive(:read).with("/unknown/path/to/file.txt") { default_keyfile_content }

      stub_token_request

      creds = TestCredentials2.default
      expect(creds).to be_a_kind_of(TestCredentials2)
      expect(creds.project_id).to eq(default_keyfile_hash["project_id"])
      expect(creds.quota_project_id).to eq(default_keyfile_hash["quota_project_id"])

      client = creds.client
      expect(client).to be_a_kind_of(Google::Auth::ServiceAccountCredentials)
      expect(client.token_credential_uri.to_s).to eq("https://oauth2.googleapis.com/token")
      expect(client.audience).to eq("https://oauth2.googleapis.com/token")
      expect(client.scope).to eq(["http://example.com/scope"])
      expect(client.instance_variable_get(:@enable_self_signed_jwt)).to eq(false)
      expect(client.target_audience).to be_nil
      expect(client.issuer).to eq(default_keyfile_hash["client_email"])
    end

    it "can use JSON_ENV_VARS to get keyfile contents" do
      test_json_env_val = JSON.generate default_keyfile_hash

      class TestCredentials3 < Google::Auth::Credentials
        SCOPE = "http://example.com/scope".freeze
        PATH_ENV_VARS = ["PATH_ENV_DUMMY"].freeze
        JSON_ENV_VARS = %w[JSON_ENV_DUMMY JSON_ENV_TEST].freeze
        DEFAULT_PATHS = ["~/default/path/to/file.txt"].freeze
      end

      allow(::ENV).to receive(:[]).with("PATH_ENV_DUMMY") { "/fake/path/to/file.txt" }
      allow(::File).to receive(:file?).with("/fake/path/to/file.txt") { false }
      allow(::File).to receive(:file?).with(test_json_env_val) { false }
      allow(::ENV).to receive(:[]).with("JSON_ENV_DUMMY") { nil }
      allow(::ENV).to receive(:[]).with("JSON_ENV_TEST") { test_json_env_val }
      allow(::ENV).to receive(:[]).with("https_proxy") { nil }
      allow(::ENV).to receive(:[]).with("HTTPS_PROXY") { nil }

      stub_token_request

      creds = TestCredentials3.default
      expect(creds).to be_a_kind_of(TestCredentials3)
      expect(creds.project_id).to eq(default_keyfile_hash["project_id"])
      expect(creds.quota_project_id).to eq(default_keyfile_hash["quota_project_id"])

      client = creds.client
      expect(client.token_credential_uri.to_s).to eq("https://oauth2.googleapis.com/token")
      expect(client.audience).to eq("https://oauth2.googleapis.com/token")
      expect(client.scope).to eq(["http://example.com/scope"])
      expect(client.instance_variable_get(:@enable_self_signed_jwt)).to eq(false)
      expect(client.target_audience).to be_nil
      expect(client.issuer).to eq(default_keyfile_hash["client_email"])
    end

    it "can use DEFAULT_PATHS to get keyfile path" do
      class TestCredentials4 < Google::Auth::Credentials
        SCOPE = "http://example.com/scope".freeze
        PATH_ENV_VARS = ["PATH_ENV_DUMMY"].freeze
        JSON_ENV_VARS = ["JSON_ENV_DUMMY"].freeze
        DEFAULT_PATHS = ["~/default/path/to/file.txt"].freeze
      end

      allow(::ENV).to receive(:[]).with("PATH_ENV_DUMMY") { "/fake/path/to/file.txt" }
      allow(::File).to receive(:file?).with("/fake/path/to/file.txt") { false }
      allow(::ENV).to receive(:[]).with("JSON_ENV_DUMMY") { nil }
      allow(::File).to receive(:file?).with("~/default/path/to/file.txt") { true }
      allow(::File).to receive(:read).with("~/default/path/to/file.txt") { default_keyfile_content }
      allow(::ENV).to receive(:[]).with("https_proxy") { nil }
      allow(::ENV).to receive(:[]).with("HTTPS_PROXY") { nil }

      stub_token_request

      creds = TestCredentials4.default
      expect(creds).to be_a_kind_of(TestCredentials4)
      expect(creds.project_id).to eq(default_keyfile_hash["project_id"])
      expect(creds.quota_project_id).to eq(default_keyfile_hash["quota_project_id"])

      client = creds.client
      expect(client).to be_a_kind_of(Google::Auth::ServiceAccountCredentials)
      expect(client.token_credential_uri.to_s).to eq("https://oauth2.googleapis.com/token")
      expect(client.audience).to eq("https://oauth2.googleapis.com/token")
      expect(client.scope).to eq(["http://example.com/scope"])
      expect(client.instance_variable_get(:@enable_self_signed_jwt)).to eq(false)
      expect(client.target_audience).to be_nil
      expect(client.issuer).to eq(default_keyfile_hash["client_email"])
    end

    it "defaults to Google::Auth.get_application_default when no matches are found" do
      class TestCredentials5 < Google::Auth::Credentials
        SCOPE = "http://example.com/scope".freeze
        PATH_ENV_VARS = ["PATH_ENV_DUMMY"].freeze
        JSON_ENV_VARS = ["JSON_ENV_DUMMY"].freeze
        DEFAULT_PATHS = ["~/default/path/to/file.txt"].freeze
      end

      allow(::ENV).to receive(:[]).with("PATH_ENV_DUMMY") { "/fake/path/to/file.txt" }
      allow(::File).to receive(:file?).with("/fake/path/to/file.txt") { false }
      allow(::ENV).to receive(:[]).with("JSON_ENV_DUMMY") { nil }
      allow(::ENV).to receive(:[]).with("OS") { nil }
      allow(::ENV).to receive(:[]).with("HOME") { nil }
      allow(::ENV).to receive(:[]).with("APPDATA") { nil }
      allow(::ENV).to receive(:[]).with("ProgramData") { nil }
      allow(::File).to receive(:file?).with("~/default/path/to/file.txt") { false }

      # stub_token_request

      overrides = Google::Cloud::Env::ComputeMetadata::Overrides.new
      overrides.add "instance/service-accounts/default/token", "12345",
                    query: { "scopes" => TestCredentials5::SCOPE },
                    headers: { "content-type" => "text/html" }
      creds = Google::Cloud.env.compute_metadata.with_overrides overrides do
        TestCredentials5.default
      end
      expect(creds).to be_a_kind_of(TestCredentials5)

      client = creds.client
      expect(client).to be_a_kind_of(Google::Auth::GCECredentials)
      expect(client.audience).to eq("https://oauth2.googleapis.com/token")
      expect(client.scope).to eq([TestCredentials5::SCOPE])
    end

    it "delegates up the class hierarchy" do
      class TestCredentials6 < Google::Auth::Credentials
        TOKEN_CREDENTIAL_URI = "https://example.com/token".freeze
        AUDIENCE = "https://example.com/audience".freeze
        SCOPE = "http://example.com/scope".freeze
        PATH_ENV_VARS = ["TEST_PATH"].freeze
        JSON_ENV_VARS = ["TEST_JSON_VARS"].freeze
        DEFAULT_PATHS = ["~/default/path/to/file.txt"]
      end

      class TestCredentials7 < TestCredentials6
      end

      expect(TestCredentials7.token_credential_uri).to eq("https://example.com/token")
      expect(TestCredentials7.audience).to eq("https://example.com/audience")
      expect(TestCredentials7.scope).to eq(["http://example.com/scope"])
      expect(TestCredentials7.env_vars).to eq(["TEST_PATH", "TEST_JSON_VARS"])
      expect(TestCredentials7.paths).to eq(["~/default/path/to/file.txt"])

      TestCredentials7::TOKEN_CREDENTIAL_URI = "https://example.com/token2"
      expect(TestCredentials7.token_credential_uri).to eq("https://example.com/token2")
      TestCredentials7::AUDIENCE = nil
      expect(TestCredentials7.audience).to eq("https://example.com/audience")
    end
  end

  describe "subclasses using class methods" do
    it "passes in other env paths" do
      test_path_env_val = "/unknown/path/to/file.txt".freeze
      test_json_env_val = JSON.generate default_keyfile_hash

      ENV["TEST_PATH"] = test_path_env_val
      ENV["TEST_JSON_VARS"] = test_json_env_val

      class TestCredentials11 < Google::Auth::Credentials
        self.token_credential_uri = "https://example.com/token"
        self.audience = "https://example.com/audience"
        self.scope = "http://example.com/scope"
        self.env_vars = ["TEST_PATH", "TEST_JSON_VARS"]
      end

      allow(::File).to receive(:file?).with(test_path_env_val) { false }
      allow(::File).to receive(:file?).with(test_json_env_val) { false }

      stub_token_request uri: "https://example.com/token"

      creds = TestCredentials11.default
      expect(creds).to be_a_kind_of(TestCredentials11)
      expect(creds.project_id).to eq(default_keyfile_hash["project_id"])
      expect(creds.quota_project_id).to eq(default_keyfile_hash["quota_project_id"])

      client = creds.client
      expect(client).to be_a_kind_of(Google::Auth::ServiceAccountCredentials)
      expect(client.token_credential_uri.to_s).to eq("https://example.com/token")
      expect(client.audience).to eq("https://example.com/audience")
      expect(client.scope).to eq(["http://example.com/scope"])
      expect(client.instance_variable_get(:@enable_self_signed_jwt)).to eq(false)
      expect(client.target_audience).to be_nil
      expect(client.issuer).to eq(default_keyfile_hash["client_email"])
    end

    it "can use PATH_ENV_VARS to get keyfile path" do
      class TestCredentials12 < Google::Auth::Credentials
        self.scope = "http://example.com/scope"
        self.env_vars = %w[PATH_ENV_DUMMY PATH_ENV_TEST JSON_ENV_DUMMY]
        self.paths = ["~/default/path/to/file.txt"]
      end

      allow(::ENV).to receive(:[]).with("PATH_ENV_DUMMY") { "/fake/path/to/file.txt" }
      allow(::File).to receive(:file?).with("/fake/path/to/file.txt") { false }
      allow(::ENV).to receive(:[]).with("PATH_ENV_TEST") { "/unknown/path/to/file.txt" }
      allow(::File).to receive(:file?).with("/unknown/path/to/file.txt") { true }
      allow(::File).to receive(:read).with("/unknown/path/to/file.txt") { default_keyfile_content }
      allow(::ENV).to receive(:[]).with("https_proxy") { nil }
      allow(::ENV).to receive(:[]).with("HTTPS_PROXY") { nil }

      stub_token_request

      creds = TestCredentials12.default
      expect(creds).to be_a_kind_of(TestCredentials12)
      expect(creds.project_id).to eq(default_keyfile_hash["project_id"])
      expect(creds.quota_project_id).to eq(default_keyfile_hash["quota_project_id"])

      client = creds.client
      expect(client).to be_a_kind_of(Google::Auth::ServiceAccountCredentials)
      expect(client.token_credential_uri.to_s).to eq("https://oauth2.googleapis.com/token")
      expect(client.audience).to eq("https://oauth2.googleapis.com/token")
      expect(client.scope).to eq(["http://example.com/scope"])
      expect(client.instance_variable_get(:@enable_self_signed_jwt)).to eq(false)
      expect(client.target_audience).to be_nil
      expect(client.issuer).to eq(default_keyfile_hash["client_email"])
    end

    it "can use JSON_ENV_VARS to get keyfile contents" do
      class TestCredentials13 < Google::Auth::Credentials
        self.scope = "http://example.com/scope"
        self.env_vars = %w[PATH_ENV_DUMMY JSON_ENV_DUMMY JSON_ENV_TEST]
        self.paths = ["~/default/path/to/file.txt"]
      end

      allow(::ENV).to receive(:[]).with("PATH_ENV_DUMMY") { "/fake/path/to/file.txt" }
      allow(::File).to receive(:file?).with("/fake/path/to/file.txt") { false }
      allow(::File).to receive(:file?).with(default_keyfile_content) { false }
      allow(::ENV).to receive(:[]).with("JSON_ENV_DUMMY") { nil }
      allow(::ENV).to receive(:[]).with("JSON_ENV_TEST") { default_keyfile_content }
      allow(::ENV).to receive(:[]).with("https_proxy") { nil }
      allow(::ENV).to receive(:[]).with("HTTPS_PROXY") { nil }

      stub_token_request

      creds = TestCredentials13.default
      expect(creds).to be_a_kind_of(TestCredentials13)
      expect(creds.project_id).to eq(default_keyfile_hash["project_id"])
      expect(creds.quota_project_id).to eq(default_keyfile_hash["quota_project_id"])

      client = creds.client
      expect(client).to be_a_kind_of(Google::Auth::ServiceAccountCredentials)
      expect(client.token_credential_uri.to_s).to eq("https://oauth2.googleapis.com/token")
      expect(client.audience).to eq("https://oauth2.googleapis.com/token")
      expect(client.scope).to eq(["http://example.com/scope"])
      expect(client.instance_variable_get(:@enable_self_signed_jwt)).to eq(false)
      expect(client.target_audience).to be_nil
      expect(client.issuer).to eq(default_keyfile_hash["client_email"])
    end

    it "can use DEFAULT_PATHS to get keyfile path" do
      class TestCredentials14 < Google::Auth::Credentials
        self.scope = "http://example.com/scope"
        self.env_vars = %w[PATH_ENV_DUMMY JSON_ENV_DUMMY]
        self.paths = ["~/default/path/to/file.txt"]
      end

      allow(::ENV).to receive(:[]).with("PATH_ENV_DUMMY") { "/fake/path/to/file.txt" }
      allow(::File).to receive(:file?).with("/fake/path/to/file.txt") { false }
      allow(::ENV).to receive(:[]).with("JSON_ENV_DUMMY") { nil }
      allow(::File).to receive(:file?).with("~/default/path/to/file.txt") { true }
      allow(::File).to receive(:read).with("~/default/path/to/file.txt") { default_keyfile_content }
      allow(::ENV).to receive(:[]).with("https_proxy") { nil }
      allow(::ENV).to receive(:[]).with("HTTPS_PROXY") { nil }

      stub_token_request

      creds = TestCredentials14.default
      expect(creds).to be_a_kind_of(TestCredentials14)
      expect(creds.project_id).to eq(default_keyfile_hash["project_id"])
      expect(creds.quota_project_id).to eq(default_keyfile_hash["quota_project_id"])

      client = creds.client
      expect(client).to be_a_kind_of(Google::Auth::ServiceAccountCredentials)
      expect(client.token_credential_uri.to_s).to eq("https://oauth2.googleapis.com/token")
      expect(client.audience).to eq("https://oauth2.googleapis.com/token")
      expect(client.scope).to eq(["http://example.com/scope"])
      expect(client.instance_variable_get(:@enable_self_signed_jwt)).to eq(false)
      expect(client.target_audience).to be_nil
      expect(client.issuer).to eq(default_keyfile_hash["client_email"])
    end

    it "defaults to Google::Auth.get_application_default with self-signed jwt enabled when no matches are found" do
      class TestCredentials15 < Google::Auth::Credentials
        self.scope = "http://example.com/scope"
        self.env_vars = %w[PATH_ENV_DUMMY JSON_ENV_DUMMY]
        self.paths = ["~/default/path/to/file.txt"]
      end

      allow(::ENV).to receive(:[]).with("PATH_ENV_DUMMY") { "/fake/path/to/file.txt" }
      allow(::File).to receive(:file?).with("/fake/path/to/file.txt") { false }
      allow(::ENV).to receive(:[]).with("JSON_ENV_DUMMY") { nil }
      allow(::File).to receive(:file?).with("~/default/path/to/file.txt") { false }
      allow(::ENV).to receive(:key?).with("GOOGLE_APPLICATION_CREDENTIALS") { true }
      allow(::ENV).to receive(:[]).with("GOOGLE_APPLICATION_CREDENTIALS") { "/adc/path/to/file.txt" }
      allow(::File).to receive(:exist?).with("/adc/path/to/file.txt") { true }
      allow(::File).to receive(:open).with("/adc/path/to/file.txt").and_yield(StringIO.new default_keyfile_content)

      creds = TestCredentials15.default enable_self_signed_jwt: true
      expect(creds).to be_a_kind_of(TestCredentials15)
      expect(creds.project_id).to eq(default_keyfile_hash["project_id"])
      expect(creds.quota_project_id).to eq(default_keyfile_hash["quota_project_id"])

      client = creds.client
      expect(client).to be_a_kind_of(Google::Auth::ServiceAccountCredentials)
      expect(client.token_credential_uri.to_s).to eq("https://oauth2.googleapis.com/token")
      expect(client.audience).to eq("https://oauth2.googleapis.com/token")
      expect(client.scope).to eq(["http://example.com/scope"])
      expect(client.instance_variable_get(:@enable_self_signed_jwt)).to eq(true)
      expect(client.target_audience).to be_nil
      expect(client.issuer).to eq(default_keyfile_hash["client_email"])
    end

    it "defaults to Google::Auth.get_application_default with self-signed jwt disabled when no matches are found" do
      class TestCredentials16 < Google::Auth::Credentials
        self.scope = "http://example.com/scope"
        self.env_vars = %w[PATH_ENV_DUMMY JSON_ENV_DUMMY]
        self.paths = ["~/default/path/to/file.txt"]
      end

      allow(::ENV).to receive(:[]).with("PATH_ENV_DUMMY") { "/fake/path/to/file.txt" }
      allow(::File).to receive(:file?).with("/fake/path/to/file.txt") { false }
      allow(::ENV).to receive(:[]).with("JSON_ENV_DUMMY") { nil }
      allow(::File).to receive(:file?).with("~/default/path/to/file.txt") { false }
      allow(::ENV).to receive(:key?).with("GOOGLE_APPLICATION_CREDENTIALS") { true }
      allow(::ENV).to receive(:[]).with("GOOGLE_APPLICATION_CREDENTIALS") { "/adc/path/to/file.txt" }
      allow(::File).to receive(:exist?).with("/adc/path/to/file.txt") { true }
      allow(::File).to receive(:open).with("/adc/path/to/file.txt").and_yield(StringIO.new default_keyfile_content)
      allow(::ENV).to receive(:[]).with("https_proxy") { nil }
      allow(::ENV).to receive(:[]).with("HTTPS_PROXY") { nil }

      stub_token_request

      creds = TestCredentials16.default
      expect(creds).to be_a_kind_of(TestCredentials16)
      expect(creds.project_id).to eq(default_keyfile_hash["project_id"])
      expect(creds.quota_project_id).to eq(default_keyfile_hash["quota_project_id"])

      client = creds.client
      expect(client).to be_a_kind_of(Google::Auth::ServiceAccountCredentials)
      expect(client.token_credential_uri.to_s).to eq("https://oauth2.googleapis.com/token")
      expect(client.audience).to eq("https://oauth2.googleapis.com/token")
      expect(client.scope).to eq(["http://example.com/scope"])
      expect(client.instance_variable_get(:@enable_self_signed_jwt)).to eq(false)
      expect(client.target_audience).to be_nil
      expect(client.issuer).to eq(default_keyfile_hash["client_email"])
    end

    it "defaults to Google::Auth.get_application_default with custom values when no matches are found" do
      scope2 = "http://example.com/scope2"

      class TestCredentials17 < Google::Auth::Credentials
        self.scope = "http://example.com/scope"
        self.env_vars = %w[PATH_ENV_DUMMY JSON_ENV_DUMMY]
        self.paths = ["~/default/path/to/file.txt"]
        self.token_credential_uri = "https://example.com/token2"
        self.audience = "https://example.com/token3"
      end

      allow(::ENV).to receive(:[]).with("PATH_ENV_DUMMY") { "/fake/path/to/file.txt" }
      allow(::File).to receive(:file?).with("/fake/path/to/file.txt") { false }
      allow(::ENV).to receive(:[]).with("JSON_ENV_DUMMY") { nil }
      allow(::File).to receive(:file?).with("~/default/path/to/file.txt") { false }
      allow(::ENV).to receive(:key?).with("GOOGLE_APPLICATION_CREDENTIALS") { true }
      allow(::ENV).to receive(:[]).with("GOOGLE_APPLICATION_CREDENTIALS") { "/adc/path/to/file.txt" }
      allow(::File).to receive(:exist?).with("/adc/path/to/file.txt") { true }
      allow(::File).to receive(:open).with("/adc/path/to/file.txt").and_yield(StringIO.new default_keyfile_content)
      allow(::ENV).to receive(:[]).with("https_proxy") { nil }
      allow(::ENV).to receive(:[]).with("HTTPS_PROXY") { nil }

      stub_token_request uri: "https://example.com/token2"

      creds = TestCredentials17.default scope: scope2
      expect(creds).to be_a_kind_of(TestCredentials17)
      expect(creds.project_id).to eq(default_keyfile_hash["project_id"])
      expect(creds.quota_project_id).to eq(default_keyfile_hash["quota_project_id"])

      client = creds.client
      expect(client).to be_a_kind_of(Google::Auth::ServiceAccountCredentials)
      expect(client.token_credential_uri.to_s).to eq("https://example.com/token2")
      expect(client.audience).to eq("https://example.com/token3")
      expect(client.scope).to eq(["http://example.com/scope2"])
      expect(client.instance_variable_get(:@enable_self_signed_jwt)).to eq(false)
      expect(client.target_audience).to be_nil
      expect(client.issuer).to eq(default_keyfile_hash["client_email"])
    end

    it "delegates up the class hierarchy" do
      class TestCredentials18 < Google::Auth::Credentials
        self.scope = "http://example.com/scope"
        self.target_audience = "https://example.com/target_audience"
        self.env_vars = ["TEST_PATH", "TEST_JSON_VARS"]
        self.paths = ["~/default/path/to/file.txt"]
      end

      class TestCredentials19 < TestCredentials18
      end

      expect(TestCredentials19.scope).to eq(["http://example.com/scope"])
      expect(TestCredentials19.target_audience).to eq("https://example.com/target_audience")
      expect(TestCredentials19.env_vars).to eq(["TEST_PATH", "TEST_JSON_VARS"])
      expect(TestCredentials19.paths).to eq(["~/default/path/to/file.txt"])

      TestCredentials19.token_credential_uri = "https://example.com/token2"
      expect(TestCredentials19.token_credential_uri).to eq("https://example.com/token2")
      TestCredentials19.token_credential_uri = nil
      expect(TestCredentials19.token_credential_uri).to eq("https://oauth2.googleapis.com/token")
    end
  end

  it "creates a service account subclass when passed only a file path" do
    class TestCredentials20 < Google::Auth::Credentials
      self.scope = "http://example.com/scope"
      self.env_vars = ["TEST_PATH", "TEST_JSON_VARS"]
      self.paths = ["~/default/path/to/file.txt"]
    end

    Dir.mktmpdir do |dir|
      keyfile = File.join dir, "keyfile.json"
      File.write keyfile, default_keyfile_content
      creds = TestCredentials20.new keyfile, enable_self_signed_jwt: true
      expect(creds.client).to be_a_kind_of(Google::Auth::ServiceAccountCredentials)
    end
  end

  it "does not fetch access token when initialized with a Signet::OAuth2::Client object that already has a token" do
    signet = Signet::OAuth2::Client.new access_token: token # Client#needs_access_token? will return false
    creds = Google::Auth::Credentials.new signet
    expect(creds.client).to eq(signet)
  end
end
