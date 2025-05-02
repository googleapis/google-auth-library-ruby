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
require "spec_helper"
require "tmpdir"

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
      "project_id"       => "a_project_id",
      "quota_project_id" => "b_project_id"
    }
  end
  let(:default_keyfile_content) { JSON.generate default_keyfile_hash }
  let(:fake_path_1) { "/fake/path/to/file.txt".freeze }
  let(:fake_path_2) { "/unknown/path/to/file.txt".freeze }
  FAKE_DEFAULT_PATH = "/default/path/to/file.txt".freeze

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

  describe "logger" do
    after :example do
      ENV["TEST_JSON_VARS"] = nil
      ENV["GOOGLE_APPLICATION_CREDENTIALS"] = nil
    end

    it "defaults to nil" do
      creds = Google::Auth::Credentials.new default_keyfile_hash
      expect(creds.logger).to be_nil
    end

    it "takes a logger on the constructor" do
      my_logger = Logger.new $stderr
      creds = Google::Auth::Credentials.new default_keyfile_hash, logger: my_logger
      expect(creds.logger).to equal(my_logger)
    end

    it "uses the logger in a provided signet client rather than a passed in logger" do
      my_logger = Logger.new $stderr
      wrong_logger = Logger.new $stderr
      signet = Signet::OAuth2::Client.new access_token: token
      signet.logger = my_logger
      creds = Google::Auth::Credentials.new signet, logger: wrong_logger
      expect(creds.logger).to equal(my_logger)
    end

    it "allows logger to be set explicitly" do
      my_logger = Logger.new $stderr
      creds = Google::Auth::Credentials.new default_keyfile_hash
      creds.logger = my_logger
      expect(creds.logger).to equal(my_logger)
    end

    class TestCredentialsForLogging < Google::Auth::Credentials
      TOKEN_CREDENTIAL_URI = "https://example.com/token".freeze
      AUDIENCE = "https://example.com/audience".freeze
      SCOPE = "http://example.com/scope".freeze
      JSON_ENV_VARS = ["TEST_JSON_VARS"].freeze
    end

    it "allows logger to be set when getting an adc-based default credential" do
      my_logger = Logger.new $stderr
      ENV["GOOGLE_APPLICATION_CREDENTIALS"] = fake_path_1
      allow(::File).to receive(:exist?).with(fake_path_1) { true }
      allow(::File).to receive(:open).with(fake_path_1).and_yield(StringIO.new default_keyfile_content)
      creds = TestCredentialsForLogging.default logger: my_logger
      expect(creds.logger).to equal(my_logger)
    end

    it "allows logger to be set when getting an io-based default credential" do
      test_json_env_val = JSON.generate default_keyfile_hash
      ENV["TEST_JSON_VARS"] = test_json_env_val
      allow(::File).to receive(:file?).with(test_json_env_val) { false }
      my_logger = Logger.new $stderr
      creds = TestCredentialsForLogging.default logger: my_logger
      expect(creds.logger).to equal(my_logger)
    end
  end

  it "uses empty paths and env_vars by default" do
    expect(Google::Auth::Credentials.paths).to eq([])
    expect(Google::Auth::Credentials.env_vars).to eq([])
  end

  describe "subclasses using CONSTANTS" do
    after :example do
      ENV["TEST_PATH"] = nil
      ENV["TEST_JSON_VARS"] = nil
      ENV["PATH_ENV_DUMMY"] = nil
      ENV["PATH_ENV_TEST"] = nil
      ENV["JSON_ENV_DUMMY"] = nil
      ENV["JSON_ENV_TEST"] = nil
    end

    it "passes in other env paths" do
      test_path_env_val = fake_path_1
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
        DEFAULT_PATHS = [FAKE_DEFAULT_PATH].freeze
      end

      ENV["PATH_ENV_DUMMY"] = fake_path_1
      ENV["PATH_ENV_TEST"] = fake_path_2
      allow(::File).to receive(:file?).with(fake_path_1) { false }
      allow(::File).to receive(:file?).with(fake_path_2) { true }
      allow(::File).to receive(:read).with(fake_path_2) { default_keyfile_content }

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
        DEFAULT_PATHS = [FAKE_DEFAULT_PATH].freeze
      end

      ENV["PATH_ENV_DUMMY"] = fake_path_1
      ENV["JSON_ENV_TEST"] = test_json_env_val
      allow(::File).to receive(:file?).with(fake_path_1) { false }
      allow(::File).to receive(:file?).with(test_json_env_val) { false }

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
        DEFAULT_PATHS = [FAKE_DEFAULT_PATH].freeze
      end

      ENV["PATH_ENV_DUMMY"] = fake_path_1
      allow(::File).to receive(:file?).with(fake_path_1) { false }
      allow(::File).to receive(:file?).with(FAKE_DEFAULT_PATH) { true }
      allow(::File).to receive(:read).with(FAKE_DEFAULT_PATH) { default_keyfile_content }

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
        DEFAULT_PATHS = [FAKE_DEFAULT_PATH].freeze
      end

      allow(::ENV).to receive(:[]).with("PATH_ENV_DUMMY") { fake_path_1 }
      allow(::File).to receive(:file?).with(fake_path_1) { false }
      allow(::ENV).to receive(:[]).with("JSON_ENV_DUMMY") { nil }
      allow(::ENV).to receive(:[]).with("OS") { nil }
      allow(::ENV).to receive(:[]).with("HOME") { nil }
      allow(::ENV).to receive(:[]).with("APPDATA") { nil }
      allow(::ENV).to receive(:[]).with("ProgramData") { nil }
      allow(::ENV).to receive(:[]).with("GOOGLE_SDK_RUBY_LOGGING_GEMS") { nil }
      allow(::File).to receive(:file?).with(FAKE_DEFAULT_PATH) { false }

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
        DEFAULT_PATHS = [FAKE_DEFAULT_PATH]
      end

      class TestCredentials7 < TestCredentials6
      end

      expect(TestCredentials7.token_credential_uri).to eq("https://example.com/token")
      expect(TestCredentials7.audience).to eq("https://example.com/audience")
      expect(TestCredentials7.scope).to eq(["http://example.com/scope"])
      expect(TestCredentials7.env_vars).to eq(["TEST_PATH", "TEST_JSON_VARS"])
      expect(TestCredentials7.paths).to eq([FAKE_DEFAULT_PATH])

      TestCredentials7::TOKEN_CREDENTIAL_URI = "https://example.com/token2"
      expect(TestCredentials7.token_credential_uri).to eq("https://example.com/token2")
      TestCredentials7::AUDIENCE = nil
      expect(TestCredentials7.audience).to eq("https://example.com/audience")
    end
  end

  describe "subclasses using class methods" do
    after :example do
      ENV["TEST_PATH"] = nil
      ENV["TEST_JSON_VARS"] = nil
      ENV["PATH_ENV_DUMMY"] = nil
      ENV["PATH_ENV_TEST"] = nil
      ENV["JSON_ENV_DUMMY"] = nil
      ENV["JSON_ENV_TEST"] = nil
      ENV["GOOGLE_APPLICATION_CREDENTIALS"] = nil
    end

    it "passes in other env paths" do
      class TestCredentials11 < Google::Auth::Credentials
        self.token_credential_uri = "https://example.com/token"
        self.audience = "https://example.com/audience"
        self.scope = "http://example.com/scope"
        self.env_vars = ["TEST_PATH", "TEST_JSON_VARS"]
      end

      test_json_env_val = JSON.generate default_keyfile_hash
      ENV["TEST_PATH"] = fake_path_2
      ENV["TEST_JSON_VARS"] = test_json_env_val
      allow(::File).to receive(:file?).with(fake_path_2) { false }
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
        self.paths = [FAKE_DEFAULT_PATH]
      end

      ENV["PATH_ENV_DUMMY"] = fake_path_1
      ENV["PATH_ENV_TEST"] = fake_path_2
      allow(::File).to receive(:file?).with(fake_path_1) { false }
      allow(::File).to receive(:file?).with(fake_path_2) { true }
      allow(::File).to receive(:read).with(fake_path_2) { default_keyfile_content }

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
        self.paths = [FAKE_DEFAULT_PATH]
      end

      ENV["PATH_ENV_DUMMY"] = fake_path_1
      ENV["JSON_ENV_TEST"] = default_keyfile_content
      allow(::File).to receive(:file?).with(fake_path_1) { false }
      allow(::File).to receive(:file?).with(default_keyfile_content) { false }

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
        self.paths = [FAKE_DEFAULT_PATH]
      end

      ENV["PATH_ENV_DUMMY"] = fake_path_1
      allow(::File).to receive(:file?).with(fake_path_1) { false }
      allow(::File).to receive(:file?).with(FAKE_DEFAULT_PATH) { true }
      allow(::File).to receive(:read).with(FAKE_DEFAULT_PATH) { default_keyfile_content }

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
        self.paths = [FAKE_DEFAULT_PATH]
      end

      ENV["PATH_ENV_DUMMY"] = fake_path_1
      ENV["GOOGLE_APPLICATION_CREDENTIALS"] = fake_path_2
      allow(::File).to receive(:file?).with(fake_path_1) { false }
      allow(::File).to receive(:file?).with(FAKE_DEFAULT_PATH) { false }
      allow(::File).to receive(:exist?).with(fake_path_2) { true }
      allow(::File).to receive(:open).with(fake_path_2).and_yield(StringIO.new default_keyfile_content)

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
        self.paths = [FAKE_DEFAULT_PATH]
      end

      ENV["PATH_ENV_DUMMY"] = fake_path_1
      ENV["GOOGLE_APPLICATION_CREDENTIALS"] = fake_path_2
      allow(::File).to receive(:file?).with(fake_path_1) { false }
      allow(::File).to receive(:file?).with(FAKE_DEFAULT_PATH) { false }
      allow(::File).to receive(:exist?).with(fake_path_2) { true }
      allow(::File).to receive(:open).with(fake_path_2).and_yield(StringIO.new default_keyfile_content)

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
        self.paths = [FAKE_DEFAULT_PATH]
        self.token_credential_uri = "https://example.com/token2"
        self.audience = "https://example.com/token3"
      end

      ENV["PATH_ENV_DUMMY"] = fake_path_1
      ENV["GOOGLE_APPLICATION_CREDENTIALS"] = fake_path_2
      allow(::File).to receive(:file?).with(fake_path_1) { false }
      allow(::File).to receive(:file?).with(FAKE_DEFAULT_PATH) { false }
      allow(::File).to receive(:exist?).with(fake_path_2) { true }
      allow(::File).to receive(:open).with(fake_path_2).and_yield(StringIO.new default_keyfile_content)

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
        self.paths = [FAKE_DEFAULT_PATH]
      end

      class TestCredentials19 < TestCredentials18
      end

      expect(TestCredentials19.scope).to eq(["http://example.com/scope"])
      expect(TestCredentials19.target_audience).to eq("https://example.com/target_audience")
      expect(TestCredentials19.env_vars).to eq(["TEST_PATH", "TEST_JSON_VARS"])
      expect(TestCredentials19.paths).to eq([FAKE_DEFAULT_PATH])

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
      self.paths = [FAKE_DEFAULT_PATH]
    end

    Dir.mktmpdir do |dir|
      keyfile = File.join dir, "keyfile.json"
      File.write keyfile, default_keyfile_content
      creds = TestCredentials20.new keyfile, enable_self_signed_jwt: true
      expect(creds.client).to be_a_kind_of(Google::Auth::ServiceAccountCredentials)
    end
  end

  it "creates a service account subclass when passed only a Pathname" do
    class TestCredentialsPathname < Google::Auth::Credentials
      self.scope = "http://example.com/scope"
    end

    Dir.mktmpdir do |dir|
      keyfile_path_str = File.join dir, "keyfile.json"
      File.write keyfile_path_str, default_keyfile_content
      keyfile_pathname = Pathname.new keyfile_path_str # Create a Pathname object
      creds = TestCredentialsPathname.new keyfile_pathname, enable_self_signed_jwt: true
      
      expect(creds.client).to be_a_kind_of(Google::Auth::ServiceAccountCredentials)
      # Verify that project_id and quota_project_id are loaded correctly from the file via Pathname
      expect(creds.project_id).to eq(default_keyfile_hash["project_id"])
      expect(creds.quota_project_id).to eq(default_keyfile_hash["quota_project_id"])
    end
  end

  it "does not fetch access token when initialized with a Signet::OAuth2::Client object that already has a token" do
    signet = Signet::OAuth2::Client.new access_token: token # Client#needs_access_token? will return false
    creds = Google::Auth::Credentials.new signet
    expect(creds.client).to eq(signet)
  end

  describe "duplicates" do
    let :client_class do
      Class.new do
        attr_accessor :scope, :project_id
        def initialize scope = nil, project_id = nil
          @scope = scope
          @project_id = project_id
        end
  
        def duplicate options = {}
          new_credentials = self.class.new
          new_credentials.scope = options[:scope] if options[:scope]
          new_credentials.project_id = options[:project_id] if options[:project_id]
          new_credentials
        end
      end
    end
  
    before :example do
      @client = client_class.new
      @base_creds = Google::Auth::Credentials.new(@client)
      @creds = @base_creds.duplicate
    end
  
    it "should call duplicate and update! on clients when clients support it" do
      client_with_duplicate = double("ClientWithDuplicate")
      allow(client_with_duplicate).to receive(:respond_to?).with(:duplicate).and_return(true)
      
      # These will be called when we create new `Google::Auth::Credentials` in this test method
      allow(client_with_duplicate).to receive(:respond_to?).with(:project_id).and_return(false)
      allow(client_with_duplicate).to receive(:respond_to?).with(:quota_project_id).and_return(false)
      allow(client_with_duplicate).to receive(:respond_to?).with(:logger=).and_return(false)

      duplicated_client = double("DuplicatedClient")
      allow(duplicated_client).to receive(:respond_to?).with(:update!).and_return(true)

      # These will be called when a new `Google::Auth::Credentials` will be created in the
      # process of the `duplicate` call. 
      # First the `client_with_duplicate` will return `duplicated_client` from its `duplicate` call
      # Then the new `Google::Auth::Credentials` will be created with the `duplicated_client`
      allow(duplicated_client).to receive(:respond_to?).with(:project_id).and_return(false)
      allow(duplicated_client).to receive(:respond_to?).with(:quota_project_id).and_return(false)
      allow(duplicated_client).to receive(:respond_to?).with(:logger=).and_return(false)
      
      #expect(duplicated_client).to receive(:update!).and_return(duplicated_client)

      expect(client_with_duplicate).to receive(:duplicate).and_return(duplicated_client)

      creds = Google::Auth::Credentials.new(client_with_duplicate)

      new_creds = creds.duplicate(foo: "bar")
      expect(new_creds.client).to eq duplicated_client
    end
  
    it "should duplicate the project_id" do
      # This should be nil, but for case of local testing
      expect(@creds.project_id).to eq Google::Auth::CredentialsLoader.load_gcloud_project_id
      expect(@creds.duplicate(project_id: "test-project-id").project_id).to eq "test-project-id"  
    end
  
    it "should duplicate the quota_project_id" do
      expect(@creds.quota_project_id).to be_nil
      expect(@creds.duplicate(quota_project_id: "test-quota-project-id").quota_project_id).to eq "test-quota-project-id"
    end
  end

  describe "when initialized with a `Google::Auth::BaseClient`" do
    let(:client_project_id) { "client_project_id_from_obj" }
    let(:client_quota_project_id) { "client_quota_id_from_obj" }
    let(:client_logger) { Logger.new(IO::NULL) } # Specific instance for client

    let(:options_project_id) { "options_project_id" }
    let(:options_quota_project_id) { "options_quota_project_id" }
    let(:options_logger) { Logger.new(IO::NULL) } # Specific instance for options, different from client_logger

    # Mock client that has project_id, quota_project_id, and logger
    let(:mock_client_full) do
      client = double("Google::Auth::BaseClientFull")
      allow(client).to receive(:respond_to?).with(:project_id).and_return(true)
      allow(client).to receive(:project_id).and_return(client_project_id)
      
      allow(client).to receive(:respond_to?).with(:quota_project_id).and_return(true)
      allow(client).to receive(:quota_project_id).and_return(client_quota_project_id)
      
      allow(client).to receive(:respond_to?).with(:logger).and_return(true)
      allow(client).to receive(:logger).and_return(client_logger)
      
      allow(client).to receive(:respond_to?).with(:logger=).and_return(true)
      allow(client).to receive(:logger=) # Allow it to be called
      client
    end

    let(:mock_client_minimal) do
      client = double("Google::Auth::BaseClientMinimal")
      allow(client).to receive(:respond_to?).with(:project_id).and_return(false)
      allow(client).to receive(:respond_to?).with(:quota_project_id).and_return(false)
      
      allow(client).to receive(:respond_to?).with(:logger).and_return(true)
      allow(client).to receive(:logger).and_return(nil)
      
      allow(client).to receive(:respond_to?).with(:logger=).and_return(true)
      allow(client).to receive(:logger=)
      client
    end

    it "uses the provided client instance as its internal client" do
      creds = Google::Auth::Credentials.new mock_client_full
      expect(creds.client).to eq(mock_client_full)
    end

    it "prefers project_id from options" do
      creds = Google::Auth::Credentials.new mock_client_full, project_id: options_project_id
      expect(creds.project_id).to eq(options_project_id)
    end

    it "prefers quota_project_id from options" do
      creds = Google::Auth::Credentials.new mock_client_full, quota_project_id: options_quota_project_id
      expect(creds.quota_project_id).to eq(options_quota_project_id)
    end

    context "logger handling" do
      # Same as the Signet test in the logger section
      it "uses the logger in a provided signet client rather than a passed in logger" do
        creds = Google::Auth::Credentials.new mock_client_full, logger: options_logger
        expect(creds.logger).to eq(client_logger) # Client's logger should win
        # Verify the final logger is pushed back to the client
        expect(mock_client_full).to have_received(:logger=).with(client_logger)
      end

      it "uses passed in logger if client does not have a logger" do
        # Scenario 1: Client doesn't respond to :logger
        creds_minimal_client = Google::Auth::Credentials.new mock_client_minimal, logger: options_logger
        expect(mock_client_minimal).to have_received(:logger=).with(options_logger)
      end

      it "has a nil logger if neither options nor client provide one (and client getter returns nil)" do
        creds = Google::Auth::Credentials.new mock_client_minimal # No logger in options
        expect(creds.logger).to be_nil
      end
    end
  end
end
