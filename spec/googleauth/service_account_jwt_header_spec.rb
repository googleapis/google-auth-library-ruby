# Copyright 2025 Google, Inc.
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

require "fakefs/safe"
require "fileutils"
require "jwt"
require "multi_json"
require "openssl"
require "spec_helper"
require "tmpdir"
require "os"

require "apply_auth_examples"
require "googleauth/service_account"
require "googleauth/service_account_jwt_header"
require "service_account/jwt_header_auth_examples"

include Google::Auth::CredentialsLoader

describe Google::Auth::ServiceAccountJwtHeaderCredentials do
  ServiceAccountJwtHeaderCredentials =
    Google::Auth::ServiceAccountJwtHeaderCredentials

  let(:client_email) { "app@developer.gserviceaccount.com" }
  let(:clz) { Google::Auth::ServiceAccountJwtHeaderCredentials }
  let :cred_json do
    {
      private_key_id: "a_private_key_id",
      private_key:    @key.to_pem,
      client_email:   client_email,
      client_id:      "app.apps.googleusercontent.com",
      type:           "service_account",
      project_id:     "a_project_id"
    }
  end

  before :example do
    @key = OpenSSL::PKey::RSA.new 2048
    @client = clz.make_creds json_key_io: StringIO.new(cred_json_text)
  end

  def cred_json_text
    MultiJson.dump cred_json
  end

  it_behaves_like "jwt header auth"

  describe "#from_env" do
    before :example do
      @var_name = ENV_VAR
      @credential_vars = [
        ENV_VAR, PRIVATE_KEY_VAR, CLIENT_EMAIL_VAR, ACCOUNT_TYPE_VAR
      ]
      @original_env_vals = {}
      @credential_vars.each { |var| @original_env_vals[var] = ENV[var] }
      ENV[ACCOUNT_TYPE_VAR] = cred_json[:type]
    end

    after :example do
      @credential_vars.each { |var| ENV[var] = @original_env_vals[var] }
    end

    it "returns nil if the GOOGLE_APPLICATION_CREDENTIALS is unset" do
      ENV.delete @var_name unless ENV[@var_name].nil?
      expect(clz.from_env).to be_nil
    end

    it "returns nil if the GOOGLE_APPLICATION_CREDENTIALS is empty" do
      ENV[@var_name] = ""
      expect(clz.from_env).to be_nil
    end

    it "fails if the GOOGLE_APPLICATION_CREDENTIALS path does not exist" do
      ENV.delete @var_name unless ENV[@var_name].nil?
      expect(clz.from_env).to be_nil
      Dir.mktmpdir do |dir|
        key_path = File.join dir, "does-not-exist"
        ENV[@var_name] = key_path
        expect { clz.from_env }.to raise_error Google::Auth::InitializationError
      end
    end

    it "succeeds when the GOOGLE_APPLICATION_CREDENTIALS file is valid" do
      Dir.mktmpdir do |dir|
        key_path = File.join dir, "my_cert_file"
        FileUtils.mkdir_p File.dirname(key_path)
        File.write key_path, cred_json_text
        ENV[@var_name] = key_path
        expect(clz.from_env).to_not be_nil
      end
    end

    it "succeeds when GOOGLE_PRIVATE_KEY and GOOGLE_CLIENT_EMAIL env vars are"\
      " valid" do
      ENV[PRIVATE_KEY_VAR] = cred_json[:private_key]
      ENV[CLIENT_EMAIL_VAR] = cred_json[:client_email]
      expect(clz.from_env(@scope)).to_not be_nil
    end

    it "sets project_id when the PROJECT_ID_VAR env var is set" do
      ENV[PRIVATE_KEY_VAR] = cred_json[:private_key]
      ENV[CLIENT_EMAIL_VAR] = cred_json[:client_email]
      ENV[PROJECT_ID_VAR] = cred_json[:project_id]
      ENV[ENV_VAR] = nil
      credentials = clz.from_env @scope
      expect(credentials).to_not be_nil
      expect(credentials.project_id).to eq(cred_json[:project_id])
    end
  end

  describe "#from_well_known_path" do
    before :example do
      @home = ENV["HOME"]
      @app_data = ENV["APPDATA"]
    end

    after :example do
      ENV["HOME"] = @home unless @home == ENV["HOME"]
      ENV["APPDATA"] = @app_data unless @app_data == ENV["APPDATA"]
    end

    it "is nil if no file exists" do
      ENV["HOME"] = File.dirname __FILE__
      expect(clz.from_well_known_path).to be_nil
    end

    it "successfully loads the file when it is present" do
      Dir.mktmpdir do |dir|
        key_path = File.join dir, ".config", WELL_KNOWN_PATH
        key_path = File.join dir, WELL_KNOWN_PATH if OS.windows?
        FileUtils.mkdir_p File.dirname(key_path)
        File.write key_path, cred_json_text
        ENV["HOME"] = dir
        ENV["APPDATA"] = dir
        expect(clz.from_well_known_path).to_not be_nil
      end
    end

    it "successfully sets project_id when file is present" do
      Dir.mktmpdir do |dir|
        key_path = File.join dir, ".config", WELL_KNOWN_PATH
        key_path = File.join dir, WELL_KNOWN_PATH if OS.windows?
        FileUtils.mkdir_p File.dirname(key_path)
        File.write key_path, cred_json_text
        ENV["HOME"] = dir
        ENV["APPDATA"] = dir
        credentials = clz.from_well_known_path @scope
        expect(credentials.project_id).to eq(cred_json[:project_id])
        expect(credentials.quota_project_id).to be_nil
      end
    end
  end

  describe "#new_jwt_token" do
    let(:test_uri) { "https://www.googleapis.com/myservice" }
    let(:auth_prefix) { "Bearer " }

    it "should return a token without Bearer prefix" do
      jwt_token = @client.new_jwt_token test_uri
      expect(jwt_token).to_not be_nil
      expect(jwt_token.start_with?(auth_prefix)).to be false
      payload, = JWT.decode jwt_token, @key.public_key, true, algorithm: "RS256"

      expect(payload["aud"]).to eq(test_uri) if not test_uri.nil?
      expect(payload["iss"]).to eq(client_email)
    end
  end

  describe "duplicates" do
    before :example do
      @creds = @client.duplicate
    end

    it "should duplicate the private_key" do
      new_key = OpenSSL::PKey::RSA.new 2048
      expect(@creds.instance_variable_get(:@private_key)).to eq @key.to_pem
      expect(@creds.duplicate(private_key: new_key.to_pem).instance_variable_get(:@private_key)).to eq new_key.to_pem
    end

    it "should duplicate the project_id" do
      expect(@creds.instance_variable_get(:@issuer)).to eq "app@developer.gserviceaccount.com"
      expect(@creds.duplicate(issuer: "test-issuer").instance_variable_get(:@issuer)).to eq "test-issuer"
    end

    it "should duplicate the project_id" do
      expect(@creds.project_id).to eq "a_project_id"
      expect(@creds.duplicate(project_id: "test-project-id-2").project_id).to eq "test-project-id-2"
    end

    it "should duplicate the quota_project_id" do
      expect(@creds.quota_project_id).to eq nil
      expect(@creds.duplicate(quota_project_id: "test-quota-project-id-2").quota_project_id).to eq "test-quota-project-id-2"
    end

    it "should duplicate the quota_project_id" do
      expect(@creds.universe_domain).to eq "googleapis.com"
      expect(@creds.duplicate(universe_domain: "test-universe-domain").universe_domain).to eq "test-universe-domain"
    end

    it "should duplicate the logger" do
      expect(@creds.logger).to be_nil
      expect(@creds.duplicate(logger: :foo).logger).to eq :foo
    end
  end
end
