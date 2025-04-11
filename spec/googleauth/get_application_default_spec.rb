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

require "faraday"
require "fakefs/safe"
require "googleauth"
require "spec_helper"
require "os"

describe "#get_application_default" do
  # Pass unique options each time to bypass memoization
  let(:options) { |example| { dememoize: example } }

  before :example do
    Google::Cloud.env.compute_smbios.override_product_name = "Google Compute Engine"
    GCECredentials.reset_cache
    @key = OpenSSL::PKey::RSA.new 2048
    @var_name = ENV_VAR
    @credential_vars = [
      ENV_VAR, PRIVATE_KEY_VAR, CLIENT_EMAIL_VAR, CLIENT_ID_VAR,
      CLIENT_SECRET_VAR, REFRESH_TOKEN_VAR, ACCOUNT_TYPE_VAR
    ]
    @original_env_vals = {}
    @credential_vars.each { |var| @original_env_vals[var] = ENV[var] }
    @home = ENV["HOME"]
    @app_data = ENV["APPDATA"]
    @program_data = ENV["ProgramData"]
    @scope = "https://www.googleapis.com/auth/userinfo.profile"
  end

  after :example do
    Google::Cloud.env.compute_smbios.override_product_name = nil
    @credential_vars.each { |var| ENV[var] = @original_env_vals[var] }
    ENV["HOME"] = @home unless @home == ENV["HOME"]
    ENV["APPDATA"] = @app_data unless @app_data == ENV["APPDATA"]
    ENV["ProgramData"] = @program_data unless @program_data == ENV["ProgramData"]
  end

  shared_examples "it cannot load misconfigured credentials" do
    it "fails if the GOOGLE_APPLICATION_CREDENTIALS path does not exist" do
      Dir.mktmpdir do |dir|
        key_path = File.join dir, "does-not-exist"
        ENV[@var_name] = key_path
        begin
          Google::Auth.get_application_default @scope, options
          fail "Expected to raise error"
        rescue => e
          expect(e).to be_a Google::Auth::InitializationError
          expect(e).to be_a Google::Auth::Error
          expect(e.message).to include "Unable to read the credential file"
          expect(e.message).to include "does-not-exist"
        end
      end
    end

    it "fails without default file or env if not on compute engine" do
      Google::Cloud.env.compute_smbios.with_override_product_name "Someone else" do
        Dir.mktmpdir do |dir|
          ENV.delete @var_name unless ENV[@var_name].nil? # no env var
          ENV["HOME"] = dir # no config present in this tmp dir
          expect do
            Google::Auth.get_application_default @scope, options
          end.to raise_error Google::Auth::InitializationError
        end
      end
    end
  end

  shared_examples "it can successfully load credentials" do
    it "succeeds if the GOOGLE_APPLICATION_CREDENTIALS file is valid" do
      Dir.mktmpdir do |dir|
        key_path = File.join dir, "my_cert_file"
        FileUtils.mkdir_p File.dirname(key_path)
        File.write key_path, cred_json_text
        ENV[@var_name] = key_path
        expect(Google::Auth.get_application_default(@scope, options))
          .to_not be_nil
      end
    end

    it "propagates default_connection option" do
      Dir.mktmpdir do |dir|
        key_path = File.join dir, "my_cert_file"
        FileUtils.mkdir_p File.dirname(key_path)
        File.write key_path, cred_json_text
        ENV[@var_name] = key_path
        connection = Faraday.new headers: { "User-Agent" => "hello" }
        opts = options.merge default_connection: connection
        creds = Google::Auth.get_application_default @scope, opts
        expect(creds.build_default_connection).to be connection
      end
    end

    it "succeeds with default file without GOOGLE_APPLICATION_CREDENTIALS" do
      ENV.delete @var_name unless ENV[@var_name].nil?
      Dir.mktmpdir do |dir|
        key_path = File.join dir, ".config", WELL_KNOWN_PATH
        key_path = File.join dir, WELL_KNOWN_PATH if OS.windows?
        FileUtils.mkdir_p File.dirname(key_path)
        File.write key_path, cred_json_text
        ENV["HOME"] = dir
        ENV["APPDATA"] = dir
        expect(Google::Auth.get_application_default(@scope, options))
          .to_not be_nil
      end
    end

    it "succeeds with default file without a scope" do
      ENV.delete @var_name unless ENV[@var_name].nil?
      Dir.mktmpdir do |dir|
        key_path = File.join dir, ".config", WELL_KNOWN_PATH
        key_path = File.join dir, WELL_KNOWN_PATH if OS.windows?
        FileUtils.mkdir_p File.dirname(key_path)
        File.write key_path, cred_json_text
        ENV["HOME"] = dir
        ENV["APPDATA"] = dir
        expect(Google::Auth.get_application_default(nil, options)).to_not be_nil
      end
    end

    describe "when on compute engine" do
      before do
        @compute_metadata_server = stub_request(:get, "http://169.254.169.254")
                                     .to_return(status: 200, headers: { "Metadata-Flavor" => "Google" })
      end

      it "succeeds without default file or env if on compute engine" do
        Dir.mktmpdir do |dir|
          ENV.delete @var_name unless ENV[@var_name].nil? # no env var
          ENV["HOME"] = dir # no config present in this tmp dir
          creds = Google::Auth.get_application_default @scope, options
          expect(creds).to_not be_nil
        end
        expect(@compute_metadata_server).to have_been_requested
      end

      it "honors passing options to OAuth 2 client" do
        gce_credentials = instance_double(GCECredentials)
        allow(GCECredentials)
          .to receive(:new).with(options.merge(scope: @scope)).and_return(gce_credentials)

        Dir.mktmpdir do |dir|
          ENV.delete @var_name unless ENV[@var_name].nil? # no env var
          ENV["HOME"] = dir # no config present in this tmp dir
          creds = Google::Auth.get_application_default @scope, options
          expect(creds).to be gce_credentials
          expect(GCECredentials).to have_received(:new).with(options.merge(scope: @scope))
        end
        expect(@compute_metadata_server).to have_been_requested
      end
    end

    it "succeeds with system default file" do
      ENV.delete @var_name unless ENV[@var_name].nil?
      FakeFS do
        ENV["ProgramData"] = "/etc"
        prefix = OS.windows? ? "/etc/Google/Auth/" : "/etc/google/auth/"
        key_path = File.join prefix, CREDENTIALS_FILE_NAME
        FileUtils.mkdir_p File.dirname(key_path)
        File.write key_path, cred_json_text
        expect(Google::Auth.get_application_default(@scope, options))
          .to_not be_nil
        File.delete key_path
      end
    end

    it "succeeds if environment vars are valid" do
      ENV.delete @var_name unless ENV[@var_name].nil? # no env var
      ENV[PRIVATE_KEY_VAR] = cred_json[:private_key]
      ENV[CLIENT_EMAIL_VAR] = cred_json[:client_email]
      ENV[CLIENT_ID_VAR] = cred_json[:client_id]
      ENV[CLIENT_SECRET_VAR] = cred_json[:client_secret]
      ENV[REFRESH_TOKEN_VAR] = cred_json[:refresh_token]
      ENV[ACCOUNT_TYPE_VAR] = cred_json[:type]
      expect(Google::Auth.get_application_default(@scope, options))
        .to_not be_nil
    end
  end

  describe "when credential type is service account" do
    let :cred_json do
      {
        private_key_id: "a_private_key_id",
        private_key:    @key.to_pem,
        client_email:   "app@developer.gserviceaccount.com",
        client_id:      "app.apps.googleusercontent.com",
        type:           "service_account"
      }
    end

    def cred_json_text
      MultiJson.dump cred_json
    end

    it_behaves_like "it can successfully load credentials"
    it_behaves_like "it cannot load misconfigured credentials"
  end

  describe "when credential type is authorized_user" do
    let :cred_json do
      {
        client_secret: "privatekey",
        refresh_token: "refreshtoken",
        client_id:     "app.apps.googleusercontent.com",
        type:          "authorized_user"
      }
    end

    def cred_json_text
      MultiJson.dump cred_json
    end

    it_behaves_like "it can successfully load credentials"
    it_behaves_like "it cannot load misconfigured credentials"
  end

  describe "when credential type is unknown" do
    let :cred_json do
      {
        client_secret: "privatekey",
        refresh_token: "refreshtoken",
        client_id:     "app.apps.googleusercontent.com",
        private_key:   @key.to_pem,
        client_email:  "app@developer.gserviceaccount.com",
        type:          "not_known_type"
      }
    end

    def cred_json_text
      MultiJson.dump cred_json
    end

    it "fails if the GOOGLE_APPLICATION_CREDENTIALS file contains the creds" do
      Dir.mktmpdir do |dir|
        key_path = File.join dir, "my_cert_file"
        FileUtils.mkdir_p File.dirname(key_path)
        File.write key_path, cred_json_text
        ENV[@var_name] = key_path
        expect do
          Google::Auth.get_application_default @scope, options
        end.to raise_error Google::Auth::InitializationError
      end
    end

    it "fails if the well known file contains the creds" do
      ENV.delete @var_name unless ENV[@var_name].nil?
      Dir.mktmpdir do |dir|
        key_path = File.join dir, ".config", WELL_KNOWN_PATH
        key_path = File.join dir, WELL_KNOWN_PATH if OS.windows?
        FileUtils.mkdir_p File.dirname(key_path)
        File.write key_path, cred_json_text
        ENV["HOME"] = dir
        ENV["APPDATA"] = dir
        expect do
          Google::Auth.get_application_default @scope, options
        end.to raise_error Google::Auth::InitializationError
      end
    end

    it "fails if env vars are set" do
      ENV[ENV_VAR] = nil
      ENV[PRIVATE_KEY_VAR] = cred_json[:private_key]
      ENV[CLIENT_EMAIL_VAR] = cred_json[:client_email]
      expect do
        Google::Auth.get_application_default @scope, options
      end.to raise_error Google::Auth::InitializationError
    end
  end
end
