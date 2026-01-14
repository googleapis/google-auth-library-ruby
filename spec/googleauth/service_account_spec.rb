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

describe Google::Auth::ServiceAccountCredentials do
  ServiceAccountCredentials = Google::Auth::ServiceAccountCredentials
  ServiceAccountJwtHeaderCredentials =
    Google::Auth::ServiceAccountJwtHeaderCredentials

  let(:client_email) { "app@developer.gserviceaccount.com" }
  let :cred_json do
    {
      private_key_id:   "a_private_key_id",
      private_key:      @key.to_pem,
      client_email:     client_email,
      client_id:        "app.apps.googleusercontent.com",
      type:             "service_account",
      project_id:       "a_project_id",
      quota_project_id: "b_project_id"
    }
  end
  let :cred_json_with_universe_domain do
    universe_data = { universe_domain: "myuniverse.com" }
    cred_json.merge universe_data
  end

  before :example do
    @key = OpenSSL::PKey::RSA.new 2048
    @client = ServiceAccountCredentials.make_creds(
      json_key_io: StringIO.new(cred_json_text),
      scope:       "https://www.googleapis.com/auth/userinfo.profile"
    )
    @non_gdu_client = ServiceAccountCredentials.make_creds(
      json_key_io: StringIO.new(cred_json_text_with_universe_domain),
      scope:       "https://www.googleapis.com/auth/userinfo.profile"
    )
    @id_client = ServiceAccountCredentials.make_creds(
      json_key_io:     StringIO.new(cred_json_text),
      target_audience: "https://pubsub.googleapis.com/"
    )
  end

  def make_auth_stubs opts
    body_fields =
      if opts[:access_token]
        { "access_token" => opts[:access_token], "token_type" => "Bearer", "expires_in" => 3600 }
      elsif opts[:id_token]
        { "id_token" => opts[:id_token] }
      else
        raise "Expected access_token or id_token"
      end
    body = MultiJson.dump body_fields
    blk = proc do |request|
      params = Addressable::URI.form_unencode request.body
      claim, _header = JWT.decode(params.assoc("assertion").last,
                                  @key.public_key, true,
                                  algorithm: "RS256")
      !opts[:id_token] || claim["target_audience"] == "https://pubsub.googleapis.com/"
    end
    stub_request(:post, "https://www.googleapis.com/oauth2/v4/token")
      .with(body: hash_including(
        "grant_type" => "urn:ietf:params:oauth:grant-type:jwt-bearer"
      ), &blk)
      .to_return(body:    body,
                 status:  200,
                 headers: { "Content-Type" => "application/json" })
  end

  def cred_json_text
    MultiJson.dump cred_json
  end

  def cred_json_text_with_universe_domain
    MultiJson.dump cred_json_with_universe_domain
  end

  it_behaves_like "apply/apply! are OK"

  it "raises an error if the credential type is not service_account" do
    cred_json[:type] = "authorized_user"
    expect do
      ServiceAccountCredentials.make_creds(
        json_key_io: StringIO.new(MultiJson.dump(cred_json))
      )
    end.to raise_error(
      Google::Auth::InitializationError,
      "The provided credentials were not of type 'service_account'. " \
      "Instead, the type was 'authorized_user'."
    )
  end

  it "succeeds if the credential type is missing (uses default)" do
    key_without_type = cred_json.reject { |k, _| k == :type }
    expect do
      ServiceAccountCredentials.make_creds(
        json_key_io: StringIO.new(MultiJson.dump(key_without_type))
      )
    end.not_to raise_error(
        Google::Auth::InitializationError, /The provided credentials were not of type 'service_account'/
    )
  end

  describe "universe_domain" do
    it "defaults to googleapis" do
      expect(@client.universe_domain).to eq("googleapis.com")
    end

    it "reads a custom domain" do
      expect(@non_gdu_client.universe_domain).to eq("myuniverse.com")
    end

    it "supports setting the universe_domain" do
      @client.universe_domain = "myuniverse.com"
      expect(@client.universe_domain).to eq("myuniverse.com")
    end
  end

  context "when scope is nil" do
    before :example do
      @client.scope = nil
    end

    it_behaves_like "jwt header auth"
  end

  context "when enable_self_signed_jwt is set with aud" do
    before :example do
      @client.scope = nil
      @client.instance_variable_set(:@enable_self_signed_jwt, true)
    end

    it_behaves_like "jwt header auth"
  end

  context "when enable_self_signed_jwt is set with scope" do
    before :example do
      @client.scope = ['scope/1', 'scope/2']
      @client.instance_variable_set(:@enable_self_signed_jwt, true)
    end

    it_behaves_like "jwt header auth", nil
  end

  context "when the universe domain is not google default" do
    before :example do
      @client.universe_domain = "myuniverse.com"
      @client.scope = ['scope/1', 'scope/2']
    end

    it_behaves_like "jwt header auth", nil
  end

  context "when target_audience is set" do
    it "retrieves an ID token with expiration" do
      expiry_time = 1608886800
      header = {
        alg: "RS256",
        kid: "1234567890123456789012345678901234567890",
        typ: "JWT"
      }
      payload = {
        aud: "http://www.example.com",
        azp: "67890",
        email: "googleapis-test@developer.gserviceaccount.com",
        email_verified: true,
        exp: expiry_time,
        iat: expiry_time - 3600,
        iss: "https://accounts.google.com",
        sub: "12345"
      }
      id_token = "#{Base64.urlsafe_encode64 JSON.dump header}.#{Base64.urlsafe_encode64 JSON.dump payload}.xxxxx"
      stub = make_auth_stubs id_token: id_token
      @id_client.fetch_access_token!
      expect(stub).to have_been_requested
      expect(@id_client.id_token).to eq(id_token)
      expect(@id_client.expires_at.to_i).to eq(expiry_time)
    end
  end

  describe "#from_env" do
    before :example do
      @var_name = ENV_VAR
      @credential_vars = [
        ENV_VAR, PRIVATE_KEY_VAR, CLIENT_EMAIL_VAR, ACCOUNT_TYPE_VAR
      ]
      @original_env_vals = {}
      @credential_vars.each { |var| @original_env_vals[var] = ENV[var] }
      ENV[ACCOUNT_TYPE_VAR] = cred_json[:type]

      @scope = "https://www.googleapis.com/auth/userinfo.profile"
      @clz = ServiceAccountCredentials
    end

    after :example do
      @credential_vars.each { |var| ENV[var] = @original_env_vals[var] }
    end

    it "returns nil if the GOOGLE_APPLICATION_CREDENTIALS is unset" do
      ENV.delete @var_name unless ENV[@var_name].nil?
      expect(ServiceAccountCredentials.from_env(@scope)).to be_nil
    end

    it "returns nil if the GOOGLE_APPLICATION_CREDENTIALS is empty" do
      ENV[@var_name] = ""
      expect(ServiceAccountCredentials.from_env(@scope)).to be_nil
    end

    it "fails if the GOOGLE_APPLICATION_CREDENTIALS path does not exist" do
      ENV.delete @var_name unless ENV[@var_name].nil?
      expect(ServiceAccountCredentials.from_env(@scope)).to be_nil
      Dir.mktmpdir do |dir|
        key_path = File.join dir, "does-not-exist"
        ENV[@var_name] = key_path
        expect { @clz.from_env @scope }.to raise_error Google::Auth::InitializationError
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

    it "succeeds when GOOGLE_PRIVATE_KEY and GOOGLE_CLIENT_EMAIL env vars are"\
      " valid" do
      ENV[PRIVATE_KEY_VAR] = cred_json[:private_key]
      ENV[CLIENT_EMAIL_VAR] = cred_json[:client_email]
      expect(@clz.from_env(@scope)).to_not be_nil
    end

    it "sets project_id when the PROJECT_ID_VAR env var is set" do
      ENV[PRIVATE_KEY_VAR] = cred_json[:private_key]
      ENV[CLIENT_EMAIL_VAR] = cred_json[:client_email]
      ENV[PROJECT_ID_VAR] = cred_json[:project_id]
      ENV[ENV_VAR] = nil
      credentials = @clz.from_env @scope
      expect(credentials.project_id).to eq(cred_json[:project_id])
    end

    it "succeeds when GOOGLE_PRIVATE_KEY is escaped" do
      escaped_key = cred_json[:private_key].gsub "\n", '\n'
      ENV[PRIVATE_KEY_VAR] = "\"#{escaped_key}\""
      ENV[CLIENT_EMAIL_VAR] = cred_json[:client_email]
      expect(@clz.from_env(@scope)).to_not be_nil
    end

    it "propagates default_connection option" do
      ENV[PRIVATE_KEY_VAR] = cred_json[:private_key]
      ENV[CLIENT_EMAIL_VAR] = cred_json[:client_email]
      connection = Faraday.new headers: { "User-Agent" => "hello" }
      creds = @clz.from_env @scope, default_connection: connection
      expect(creds.build_default_connection).to be connection
    end
  end

  describe "#from_well_known_path" do
    before :example do
      @home = ENV["HOME"]
      @app_data = ENV["APPDATA"]
      @scope = "https://www.googleapis.com/auth/userinfo.profile"
      @known_path = WELL_KNOWN_PATH
      @clz = ServiceAccountCredentials
    end

    after :example do
      ENV["HOME"] = @home unless @home == ENV["HOME"]
      ENV["APPDATA"] = @app_data unless @app_data == ENV["APPDATA"]
    end

    it "is nil if no file exists" do
      ENV["HOME"] = File.dirname __FILE__
      expect(ServiceAccountCredentials.from_well_known_path(@scope)).to be_nil
    end

    it "successfully loads the file when it is present" do
      Dir.mktmpdir do |dir|
        key_path = File.join dir, ".config", @known_path
        key_path = File.join dir, WELL_KNOWN_PATH if OS.windows?
        FileUtils.mkdir_p File.dirname(key_path)
        File.write key_path, cred_json_text
        ENV["HOME"] = dir
        ENV["APPDATA"] = dir
        expect(@clz.from_well_known_path(@scope)).to_not be_nil
      end
    end

    it "successfully sets project_id when file is present" do
      Dir.mktmpdir do |dir|
        key_path = File.join dir, ".config", @known_path
        key_path = File.join dir, WELL_KNOWN_PATH if OS.windows?
        FileUtils.mkdir_p File.dirname(key_path)
        File.write key_path, cred_json_text
        ENV["HOME"] = dir
        ENV["APPDATA"] = dir
        credentials = @clz.from_well_known_path @scope
        expect(credentials.project_id).to eq(cred_json[:project_id])
        expect(credentials.quota_project_id).to eq(cred_json[:quota_project_id])
      end
    end

    it "propagates default_connection option" do
      Dir.mktmpdir do |dir|
        key_path = File.join dir, ".config", @known_path
        key_path = File.join dir, WELL_KNOWN_PATH if OS.windows?
        FileUtils.mkdir_p File.dirname(key_path)
        File.write key_path, cred_json_text
        ENV["HOME"] = dir
        ENV["APPDATA"] = dir
        connection = Faraday.new headers: { "User-Agent" => "hello" }
        creds = @clz.from_well_known_path @scope, default_connection: connection
        expect(creds.build_default_connection).to be connection
      end
    end
  end

  describe "#from_system_default_path" do
    before :example do
      @scope = "https://www.googleapis.com/auth/userinfo.profile"
      @program_data = ENV["ProgramData"]
      @prefix = OS.windows? ? "/etc/Google/Auth/" : "/etc/google/auth/"
      @path = File.join @prefix, CREDENTIALS_FILE_NAME
      @clz = ServiceAccountCredentials
    end

    after :example do
      ENV["ProgramData"] = @program_data
    end

    it "is nil if no file exists" do
      FakeFS do
        expect(ServiceAccountCredentials.from_system_default_path(@scope))
          .to be_nil
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

    it "propagates default_connection option" do
      FakeFS do
        ENV["ProgramData"] = "/etc"
        FileUtils.mkdir_p File.dirname(@path)
        File.write @path, cred_json_text
        connection = Faraday.new headers: { "User-Agent" => "hello" }
        creds = @clz.from_system_default_path @scope, default_connection: connection
        expect(creds.build_default_connection).to be connection
        File.delete @path
      end
    end
  end
   
  describe "duplicates" do
    before :example do
      @clz = ServiceAccountCredentials
      @base_creds = @clz.make_creds(
         json_key_io: StringIO.new(cred_json_text), 
         scope: ["https://www.googleapis.com/auth/cloud-platform"]
      )
      @creds = @base_creds.duplicate
    end

    it "should duplicate the scope" do
      expect(@creds.scope).to eq ["https://www.googleapis.com/auth/cloud-platform"]
      expect(@creds.duplicate(scope: ["https://www.googleapis.com/auth/devstorage.read_only"]).scope).to eq ["https://www.googleapis.com/auth/devstorage.read_only"]
    end

    it "should duplicate the project_id" do
      expect(@creds.project_id).to eq "a_project_id"
      expect(@creds.duplicate(project_id: "test-project-id-2").project_id).to eq "test-project-id-2"
    end

    it "should duplicate the quota_project_id" do
      expect(@creds.quota_project_id).to eq "b_project_id"
      expect(@creds.duplicate(quota_project_id: "test-quota-project-id-2").quota_project_id).to eq "test-quota-project-id-2"
    end

    it "should duplicate the enable_self_signed_jwt" do
      expect(@creds.enable_self_signed_jwt?).to eq false
      expect(@creds.duplicate(enable_self_signed_jwt: true).enable_self_signed_jwt?).to eq true
    end
  end
end
