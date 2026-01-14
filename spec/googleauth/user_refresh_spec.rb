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

spec_dir = File.expand_path File.join(File.dirname(__FILE__))
$LOAD_PATH.unshift spec_dir
$LOAD_PATH.uniq!

require "apply_auth_examples"
require "fakefs/safe"
require "fileutils"
require "googleauth/user_refresh"
require "jwt"
require "multi_json"
require "openssl"
require "spec_helper"
require "tmpdir"
require "os"

include Google::Auth::CredentialsLoader

describe Google::Auth::UserRefreshCredentials do
  UserRefreshCredentials = Google::Auth::UserRefreshCredentials

  let :cred_json do
    {
      client_secret: "privatekey",
      client_id:     "client123",
      refresh_token: "refreshtoken",
      type:          "authorized_user",
      quota_project_id: "test_project"
    }
  end
  let :cred_json_with_universe_domain do
    universe_data = { universe_domain: "myuniverse.com" }
    cred_json.merge universe_data
  end

  before :example do
    @key = OpenSSL::PKey::RSA.new 2048
    @client = UserRefreshCredentials.make_creds(
      json_key_io: StringIO.new(cred_json_text),
      scope:       "https://www.googleapis.com/auth/userinfo.profile"
    )
    @non_gdu_client = UserRefreshCredentials.make_creds(
      json_key_io: StringIO.new(cred_json_text_with_universe_domain),
      scope:       "https://www.googleapis.com/auth/userinfo.profile"
    )
  end

  def make_auth_stubs opts
    access_token = opts[:access_token] || ""
    body = MultiJson.dump("access_token" => access_token,
                          "token_type"   => "Bearer",
                          "expires_in"   => 3600)
    stub_request(:post, "https://oauth2.googleapis.com/token")
      .with(body: hash_including("grant_type" => "refresh_token"))
      .to_return(body:    body,
                 status:  200,
                 headers: { "Content-Type" => "application/json" })
  end

  def cred_json_text missing = nil
    cred_json.delete missing.to_sym unless missing.nil?
    MultiJson.dump cred_json
  end

  def cred_json_text_with_universe_domain missing = nil
    cred_json_with_universe_domain.delete missing.to_sym unless missing.nil?
    MultiJson.dump cred_json_with_universe_domain
  end

  it_behaves_like "apply/apply! are OK"

  it "raises an error if the credential type is not authorized_user" do
    cred_json[:type] = "service_account"
    expect do
      UserRefreshCredentials.make_creds(
        json_key_io: StringIO.new(MultiJson.dump(cred_json))
      )
    end.to raise_error(
      Google::Auth::InitializationError,
      "The provided credentials were not of type 'authorized_user'. " \
      "Instead, the type was 'service_account'."
    )
  end

  it "succeeds if the credential type is missing (uses default)" do
    key_without_type = cred_json.reject { |k, _| k == :type }
    expect do
      UserRefreshCredentials.make_creds(
        json_key_io: StringIO.new(MultiJson.dump(key_without_type))
      )
    end.not_to raise_error(
        Google::Auth::InitializationError, /The provided credentials were not of type 'authorized_user'/
    )
  end

  describe "#from_env" do
    before :example do
      @var_name = ENV_VAR
      @credential_vars = [
        ENV_VAR, CLIENT_ID_VAR, CLIENT_SECRET_VAR, REFRESH_TOKEN_VAR,
        ACCOUNT_TYPE_VAR
      ]
      @original_env_vals = {}
      @credential_vars.each { |var| @original_env_vals[var] = ENV[var] }
      @scope = "https://www.googleapis.com/auth/userinfo.profile"
      @clz = UserRefreshCredentials
      @project_id = "a_project_id"
    end

    after :example do
      @credential_vars.each { |var| ENV[var] = @original_env_vals[var] }
    end

    it "returns nil if the GOOGLE_APPLICATION_CREDENTIALS is unset" do
      ENV.delete @var_name unless ENV[@var_name].nil?
      expect(UserRefreshCredentials.from_env(@scope)).to be_nil
    end

    it "returns nil if the GOOGLE_APPLICATION_CREDENTIALS is empty" do
      ENV[@var_name] = ""
      expect(UserRefreshCredentials.from_env(@scope)).to be_nil
    end

    it "fails if the GOOGLE_APPLICATION_CREDENTIALS path does not exist" do
      ENV.delete @var_name unless ENV[@var_name].nil?
      expect(UserRefreshCredentials.from_env(@scope)).to be_nil
      Dir.mktmpdir do |dir|
        key_path = File.join dir, "does-not-exist"
        ENV[@var_name] = key_path
        expect { @clz.from_env @scope }.to raise_error Google::Auth::InitializationError
      end
    end

    it "fails if the GOOGLE_APPLICATION_CREDENTIALS path file is invalid" do
      needed = %w[client_id client_secret refresh_token]
      needed.each do |missing|
        Dir.mktmpdir do |dir|
          key_path = File.join dir, "my_cert_file"
          FileUtils.mkdir_p File.dirname(key_path)
          File.write key_path, cred_json_text(missing)
          ENV[@var_name] = key_path
          expect { @clz.from_env @scope }.to raise_error Google::Auth::InitializationError
        end
      end
    end

    it "succeeds when the GOOGLE_APPLICATION_CREDENTIALS file is valid" do
      Dir.mktmpdir do |dir|
        key_path = File.join dir, "my_cert_file"
        FileUtils.mkdir_p File.dirname(key_path)
        File.write key_path, cred_json_text
        ENV[@var_name] = key_path
        expect(@clz.from_env(@scope)).to_not be_nil
      end
    end

    it "succeeds when GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and "\
      "GOOGLE_REFRESH_TOKEN env vars are valid" do
      ENV[ENV_VAR] = nil
      ENV[CLIENT_ID_VAR] = cred_json[:client_id]
      ENV[CLIENT_SECRET_VAR] = cred_json[:client_secret]
      ENV[REFRESH_TOKEN_VAR] = cred_json[:refresh_token]
      ENV[ACCOUNT_TYPE_VAR] = cred_json[:type]
      creds = @clz.from_env @scope
      expect(creds).to_not be_nil
      expect(creds.client_id).to eq(cred_json[:client_id])
      expect(creds.client_secret).to eq(cred_json[:client_secret])
      expect(creds.refresh_token).to eq(cred_json[:refresh_token])
      expect(creds.quota_project_id).to be_nil
    end

    it "sets project_id when the PROJECT_ID_VAR env var is set" do
      ENV[ENV_VAR] = nil
      ENV[CLIENT_ID_VAR] = cred_json[:client_id]
      ENV[CLIENT_SECRET_VAR] = cred_json[:client_secret]
      ENV[REFRESH_TOKEN_VAR] = cred_json[:refresh_token]
      ENV[ACCOUNT_TYPE_VAR] = cred_json[:type]
      ENV[PROJECT_ID_VAR] = @project_id
      creds = @clz.from_env @scope
      expect(creds.project_id).to eq(@project_id)
    end
  end

  describe "#from_well_known_path" do
    before :example do
      @home = ENV["HOME"]
      @app_data = ENV["APPDATA"]
      @scope = "https://www.googleapis.com/auth/userinfo.profile"
      @known_path = WELL_KNOWN_PATH
      @clz = UserRefreshCredentials
    end

    after :example do
      ENV["HOME"] = @home unless @home == ENV["HOME"]
      ENV["APPDATA"] = @app_data unless @app_data == ENV["APPDATA"]
    end

    it "is nil if no file exists" do
      ENV["HOME"] = File.dirname __FILE__
      expect(UserRefreshCredentials.from_well_known_path(@scope)).to be_nil
    end

    it "fails if the file is invalid" do
      needed = %w[client_id client_secret refresh_token]
      needed.each do |missing|
        Dir.mktmpdir do |dir|
          key_path = File.join dir, ".config", @known_path
          key_path = File.join dir, @known_path if OS.windows?
          FileUtils.mkdir_p File.dirname(key_path)
          File.write key_path, cred_json_text(missing)
          ENV["HOME"] = dir
          ENV["APPDATA"] = dir
          expect { @clz.from_well_known_path @scope }
            .to raise_error Google::Auth::InitializationError
        end
      end
    end

    it "successfully loads the file when it is present" do
      Dir.mktmpdir do |dir|
        key_path = File.join dir, ".config", @known_path
        key_path = File.join dir, @known_path if OS.windows?
        FileUtils.mkdir_p File.dirname(key_path)
        File.write key_path, cred_json_text
        ENV["HOME"] = dir
        ENV["APPDATA"] = dir
        expect(@clz.from_well_known_path(@scope)).to_not be_nil
      end
    end

    it "checks gcloud config for project_id if none was provided" do
      Dir.mktmpdir do |dir|
        key_path = File.join dir, ".config", @known_path
        key_path = File.join dir, @known_path if OS.windows?
        FileUtils.mkdir_p File.dirname(key_path)
        File.write key_path, cred_json_text
        ENV["HOME"] = dir
        ENV["APPDATA"] = dir
        ENV[PROJECT_ID_VAR] = nil
        expect(Google::Auth::CredentialsLoader).to receive(:load_gcloud_project_id).with(no_args)
        @clz.from_well_known_path @scope
      end
    end
  end

  describe "#from_system_default_path" do
    before :example do
      @scope = "https://www.googleapis.com/auth/userinfo.profile"
      @prefix = OS.windows? ? "/etc/Google/Auth/" : "/etc/google/auth/"
      @path = File.join @prefix, CREDENTIALS_FILE_NAME
      @program_data = ENV["ProgramData"]
      @clz = UserRefreshCredentials
    end

    after :example do
      ENV["ProgramData"] = @program_data
    end

    it "is nil if no file exists" do
      FakeFS do
        expect(UserRefreshCredentials.from_system_default_path(@scope))
          .to be_nil
      end
    end

    it "fails if the file is invalid" do
      needed = %w[client_id client_secret refresh_token]
      needed.each do |missing|
        FakeFS do
          ENV["ProgramData"] = "/etc"
          FileUtils.mkdir_p File.dirname(@path)
          File.write @path, cred_json_text(missing)
          expect { @clz.from_system_default_path @scope }
            .to raise_error Google::Auth::InitializationError
          File.delete @path
        end
      end
    end

    it "successfully loads the file when it is present" do
      FakeFS do
        ENV["ProgramData"] = "/etc"
        FileUtils.mkdir_p File.dirname(@path)
        File.write @path, cred_json_text
        expect(@clz.from_system_default_path(@scope)).to_not be_nil
        File.delete @path
      end
    end
  end

  describe "#universe_domain" do
    it "loads the default domain" do
      expect(@client.universe_domain).to eq("googleapis.com")
    end

    it "loads a custom domain" do
      expect(@non_gdu_client.universe_domain).to eq("myuniverse.com")
    end
  end

  shared_examples "revoked token" do
    it "should nil the refresh token" do
      expect(@client.refresh_token).to be_nil
    end

    it "should nil the access token" do
      expect(@client.access_token).to be_nil
    end

    it "should mark the token as expired" do
      expect(@client.expired?).to be_truthy
    end
  end

  describe "when revoking a refresh token" do
    let :stub do
      stub_request(:post, "https://oauth2.googleapis.com/revoke")
        .with(body: hash_including("token" => "refreshtoken"))
        .to_return(status:  200,
                   headers: { "Content-Type" => "application/json" })
    end

    before :example do
      stub
      @client.revoke!
    end

    it_behaves_like "revoked token"
  end

  describe "when revoking an access token" do
    let :stub do
      stub_request(:post, "https://oauth2.googleapis.com/revoke")
        .with(body: hash_including("token" => "accesstoken"))
        .to_return(status:  200,
                   headers: { "Content-Type" => "application/json" })
    end

    before :example do
      stub
      @client.refresh_token = nil
      @client.access_token = "accesstoken"
      @client.revoke!
    end

    it_behaves_like "revoked token"
  end

  describe "when revoking an invalid token" do
    let :stub do
      stub_request(:post, "https://oauth2.googleapis.com/revoke")
        .with(body: hash_including("token" => "refreshtoken"))
        .to_return(status:  400,
                   headers: { "Content-Type" => "application/json" })
    end

    it "raises an authorization error with detailed information" do
      stub
      expect { @client.revoke! }.to raise_error do |error|
        expect(error).to be_a(Google::Auth::AuthorizationError)
        expect(error.message).to match(/Unexpected error code 400/)
        expect(error.credential_type_name).to eq("Google::Auth::UserRefreshCredentials")
        expect(error.principal).to eq(@client.client_id)
      end
    end
  end

  describe "when errors occurred with request" do
    it "should fail with Signet::AuthorizationError if request times out" do
      allow_any_instance_of(Faraday::Connection).to receive(:post)
        .and_raise(Faraday::TimeoutError)
      expect { @client.revoke! }
        .to raise_error Signet::AuthorizationError
    end

    it "should fail with Signet::AuthorizationError if request fails" do
      allow_any_instance_of(Faraday::Connection).to receive(:post)
        .and_raise(Faraday::ConnectionFailed, nil)
      expect { @client.revoke! }
        .to raise_error Signet::AuthorizationError
    end
  end

  describe "duplicates" do
    before :example do
      @key = OpenSSL::PKey::RSA.new 2048
      @base_creds = UserRefreshCredentials.make_creds(
        json_key_io: StringIO.new(cred_json_text),
        scope:       "https://www.googleapis.com/auth/cloud-platform",
      )

      @creds = @base_creds.duplicate
    end

    it "should duplicate the scope" do
      expect(@creds.scope).to eq ["https://www.googleapis.com/auth/cloud-platform"]
      expect(@creds.duplicate(scope: ["https://www.googleapis.com/auth/devstorage.read_only"]).scope).to eq ["https://www.googleapis.com/auth/devstorage.read_only"]
    end

    it "should duplicate the project_id" do
      expect(@creds.project_id).to eq nil
      expect(@creds.duplicate(project_id: "test-project-id-2").project_id).to eq "test-project-id-2"
    end

    it "should duplicate the quota_project_id" do
      expect(@creds.quota_project_id).to eq "test_project"
      expect(@creds.duplicate(quota_project_id: "test-quota-project-id-2").quota_project_id).to eq "test-quota-project-id-2"
    end
  end
end
