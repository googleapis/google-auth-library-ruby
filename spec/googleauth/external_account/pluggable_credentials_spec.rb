# Copyright 2023 Google, Inc.
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

require 'webmock/rspec'
require 'googleauth'
require 'googleauth/external_account/pluggable_credentials'
require 'rbconfig'
require 'tempfile'

include Google::Auth::CredentialsLoader

CLIENT_ID = "username"
CLIENT_SECRET = "password"
# Base64 encoding of "username:password".
BASIC_AUTH_ENCODING = "dXNlcm5hbWU6cGFzc3dvcmQ="
SERVICE_ACCOUNT_EMAIL = "service-1234@service-name.iam.gserviceaccount.com"
SERVICE_ACCOUNT_IMPERSONATION_URL_BASE = "https://us-east1-iamcredentials.googleapis.com"
SERVICE_ACCOUNT_IMPERSONATION_URL_ROUTE = "/v1/projects/-/serviceAccounts/#{SERVICE_ACCOUNT_EMAIL}:generateAccessToken"
SERVICE_ACCOUNT_IMPERSONATION_URL = SERVICE_ACCOUNT_IMPERSONATION_URL_BASE + SERVICE_ACCOUNT_IMPERSONATION_URL_ROUTE
QUOTA_PROJECT_ID = "QUOTA_PROJECT_ID"
SCOPES = ["scope1", "scope2"]
SUBJECT_TOKEN_FIELD_NAME = "access_token"

TOKEN_URL = "https://sts.googleapis.com/v1/token"
TOKEN_INFO_URL = "https://sts.googleapis.com/v1/introspect"
SUBJECT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"
AUDIENCE = "//iam.googleapis.com/projects/123456/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID"
DEFAULT_UNIVERSE_DOMAIN = "googleapis.com"

describe Google::Auth::ExternalAccount::PluggableAuthCredentials do
  PluggableAuthCredentials = Google::Auth::ExternalAccount::PluggableAuthCredentials
  CREDENTIAL_SOURCE_EXECUTABLE_COMMAND = "/fake/external/excutable --arg1=value1 --arg2=value2"
  CREDENTIAL_SOURCE_EXECUTABLE_OUTPUT_FILE = "fake_output_file"
  CREDENTIAL_SOURCE_EXECUTABLE = {
    "command": CREDENTIAL_SOURCE_EXECUTABLE_COMMAND,
    "timeout_millis": 30000,
    "output_file": CREDENTIAL_SOURCE_EXECUTABLE_OUTPUT_FILE,
  }
  CREDENTIAL_SOURCE = {"executable": CREDENTIAL_SOURCE_EXECUTABLE}
  EXECUTABLE_OIDC_TOKEN = "FAKE_ID_TOKEN"
  EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_ID_TOKEN = {
    "version": 1,
    "success": true,
    "token_type": "urn:ietf:params:oauth:token-type:id_token",
    "id_token": EXECUTABLE_OIDC_TOKEN,
    "expiration_time": 9999999999,
  }
  EXECUTABLE_SUCCESSFUL_OIDC_NO_EXPIRATION_TIME_RESPONSE_ID_TOKEN = {
    "version": 1,
    "success": true,
    "token_type": "urn:ietf:params:oauth:token-type:id_token",
    "id_token": EXECUTABLE_OIDC_TOKEN,
  }
  EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_JWT = {
    "version": 1,
    "success": true,
    "token_type": "urn:ietf:params:oauth:token-type:jwt",
    "id_token": EXECUTABLE_OIDC_TOKEN,
    "expiration_time": 9999999999,
  }
  EXECUTABLE_SUCCESSFUL_OIDC_NO_EXPIRATION_TIME_RESPONSE_JWT = {
    "version": 1,
    "success": true,
    "token_type": "urn:ietf:params:oauth:token-type:jwt",
    "id_token": EXECUTABLE_OIDC_TOKEN,
  }
  EXECUTABLE_SAML_TOKEN = "FAKE_SAML_RESPONSE"
  EXECUTABLE_SUCCESSFUL_SAML_RESPONSE = {
    "version": 1,
    "success": true,
    "token_type": "urn:ietf:params:oauth:token-type:saml2",
    "saml_response": EXECUTABLE_SAML_TOKEN,
    "expiration_time": 9999999999,
  }
  EXECUTABLE_SUCCESSFUL_SAML_NO_EXPIRATION_TIME_RESPONSE = {
    "version": 1,
    "success": true,
    "token_type": "urn:ietf:params:oauth:token-type:saml2",
    "saml_response": EXECUTABLE_SAML_TOKEN,
  }
  EXECUTABLE_FAILED_RESPONSE = {
    "version": 1,
    "success": false,
    "code": "401",
    "message": "Permission denied. Caller not authorized",
  }
  CREDENTIAL_URL = "http://fakeurl.com"

  # The executable specs run real executables: throwaway Ruby scripts, so the specs go
  # through real pipes, exit codes and signals. --disable-all makes the script start fast
  # and ignore the RUBYOPT=-rbundler/setup that it inherits from `bundle exec`.
  def fake_executable_command script
    file = Tempfile.new ["fake_executable", ".rb"]
    file.write script
    file.close
    (@fake_executables ||= []) << file
    "#{RbConfig.ruby} --disable-all #{file.path}"
  end

  # Returns a command for an executable that writes stdout and stderr, then exits with exit_status.
  def fake_executable_returning stdout:, stderr:, exit_status:
    fake_executable_command "$stdout.write #{stdout.dump}\n$stderr.write #{stderr.dump}\nexit #{exit_status}\n"
  end

  # Returns a copy of options with a credential source that runs command.
  def with_executable options, command, timeout_millis: nil
    executable = { command: command }
    executable[:timeout_millis] = timeout_millis unless timeout_millis.nil?
    options.merge credential_source: { executable: executable }
  end

  # Records the pid of each executable that is started. Open3 passes every process that it
  # spawns to Process.detach, which still runs as usual.
  def record_executable_pids
    pids = []
    allow(Process).to receive(:detach).and_wrap_original do |detach, pid|
      pids << pid
      detach.call pid
    end
    pids
  end

  # True once the process has exited and been reaped, so it is no longer a child of this
  # process. Unlike Process.kill(0, pid), this cannot be fooled by a reused pid.
  def reaped? pid
    Process.waitpid pid, Process::WNOHANG
    false
  rescue Errno::ECHILD
    true
  end

  after :example do
    @fake_executables&.each(&:close!)
  end

  #####################
  #
  #  Test Cases
  #
  #####################

  describe "test initialization" do
    examples = [
      {
        name: "from full options",
        options: {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :token_info_url => nil,
          :service_account_impersonation_url => nil,
          :service_account_impersonation_options => {},
          :client_id => nil,
          :client_secret => nil,
          :credential_source => CREDENTIAL_SOURCE,
          :quota_project_id => nil,
          :workforce_pool_user_project => nil,
          :universe_domain => DEFAULT_UNIVERSE_DOMAIN,
        },
        expect_result: PluggableAuthCredentials
      },
      {
        :name => "from required options",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => CREDENTIAL_SOURCE,
        },
        :expect_result => PluggableAuthCredentials
      },
      {
        :name => "Missing executable source",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => {},
        },
        :expect_error => /Missing excutable source. An 'executable' must be provided/
      },
      {
        :name => "Missing executable command",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => { executable: {} },
        },
        :expect_error => /Missing command field. Executable command must be provided./
      },
      {
        :name => "Timeout shorter than lower bound",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => {
            executable: {
              command: "dummy command",
              timeout_millis: 2000,
            }
          },
        },
        :expect_error => /Timeout must be between 5 and 120 seconds./
      },
      {
        :name => "Timeout longer than upper bound",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => {
            executable: {
              command: "dummy command",
              timeout_millis: 120001,
            }
          },
        },
        :expect_error => /Timeout must be between 5 and 120 seconds./
      },
    ]
    examples.each do |example|
      it example[:name] do
        if example[:expect_error].nil?
          expect(PluggableAuthCredentials.new example[:options]).to be_a(example[:expect_result])
        else
          expect{PluggableAuthCredentials.new example[:options]}.to raise_error(example[:expect_error])
        end
      end
    end
  end

  describe "test retrieve subject token failed on not enabled" do
    options = {
      :audience => AUDIENCE,
      :subject_token_type => SUBJECT_TOKEN_TYPE,
      :token_url => TOKEN_URL,
      :credential_source => CREDENTIAL_SOURCE,
    }
    credentials = PluggableAuthCredentials.new options
    before :example do
      ENV[Google::Auth::ExternalAccount::PluggableAuthCredentials::ENABLE_PLUGGABLE_ENV] = "0"
    end
    it 'not enabled' do
      expect{credentials.retrieve_subject_token!}.to raise_error(/Executables need to be explicitly allowed/)
    end
  end

  describe "test retrieve subject token from cache file" do
    examples = [
      {
        :name => "id token",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => {
            :executable => {
              :command => "command",
              :output_file => "id_token_cache"
            }
          }
        },
        :file_content => JSON.generate(EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_ID_TOKEN),
        :expect_token => EXECUTABLE_OIDC_TOKEN
      },
      {
        :name => "jwt token",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => {
            :executable => {
              :command => "command",
              :output_file => "jwt_token_cache"
            }
          }
        },
        :file_content => JSON.generate(EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_JWT),
        :expect_token => EXECUTABLE_OIDC_TOKEN
      },
      {
        :name => "smal token",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
          :credential_source => {
            :executable => {
              :command => "command",
              :output_file => "saml_token_cache"
            }
          }
        },
        :file_content => JSON.generate(EXECUTABLE_SUCCESSFUL_SAML_RESPONSE),
        :expect_token => EXECUTABLE_SAML_TOKEN
      }
    ]
    examples.each do |example|
      before :example do
        file_path = example[:options][:credential_source][:executable][:output_file]
        allow(File).to receive(:exist?).with(file_path).and_return(true)
        allow(File).to receive(:read).with(file_path, encoding: "utf-8").and_return(example[:file_content])
        ENV[Google::Auth::ExternalAccount::PluggableAuthCredentials::ENABLE_PLUGGABLE_ENV] = "1"
      end
      it example[:name] do
        credentials = PluggableAuthCredentials.new example[:options]
        expect(credentials.retrieve_subject_token!).to eql(example[:expect_token])
      end
    end
  end

  describe "test retrieve subject token executable error" do
    options = {
      :audience => AUDIENCE,
      :subject_token_type => SUBJECT_TOKEN_TYPE,
      :token_url => TOKEN_URL,
      :credential_source => CREDENTIAL_SOURCE,
    }
    before :example do
      ENV[Google::Auth::ExternalAccount::PluggableAuthCredentials::ENABLE_PLUGGABLE_ENV] = "1"
      allow(Open3).to receive(:popen3).and_raise(StandardError, "mock subprocess error")
    end
    it "executable subprocess error" do
      credentials = PluggableAuthCredentials.new options
      expect{credentials.retrieve_subject_token!}.to raise_error(/mock subprocess error/)
    end
  end

  describe "test retrieve subject token executable works but response error" do
    examples = [
      {
        :name => "non-zero return",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
        },
        :executable_return => {
          :stdout => "",
          :stderr => "",
          :exit_status => 1,
        },
        :expect_error => /Executable exited with non-zero return code/
      },
      {
        :name => "malformed response no version",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
        },
        :executable_return => {
          :stdout => JSON.generate({}),
          :stderr => "",
          :exit_status => 0,
        },
        :expect_error => /The executable response is missing the version field./
      },
      {
        :name => "malformed response no success status",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
        },
        :executable_return => {
          :stdout => JSON.generate({:version => 1}),
          :stderr => "",
          :exit_status => 0
        },
        :expect_error => /The executable response is missing the success field./
      },
      {
        :name => "malformed response no error code",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
        },
        :executable_return => {
          :stdout => JSON.generate({:version => 1, :success => false}),
          :stderr => "",
          :exit_status => 0
        },
        :expect_error => /Error code and message fields are required in the response./
      },
      {
        :name => "error response",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
        },
        :executable_return => {
          :stdout => JSON.generate(EXECUTABLE_FAILED_RESPONSE),
          :stderr => "",
          :exit_status => 0
        },
        :expect_error => /Executable returned unsuccessful response:/
      },
      {
        :name => "expired token",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
        },
        :executable_return => {
          :stdout => JSON.generate({
            :version => 1,
            :success => true,
            :token_type => "urn:ietf:params:oauth:token-type:id_token",
            :id_token => EXECUTABLE_OIDC_TOKEN,
            :expiration_time => 0,
          }),
          :stderr => "",
          :exit_status => 0
        },
        :expect_error => /The token returned by the executable is expired./
      },
      {
        :name => "missing token type",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
        },
        :executable_return => {
          :stdout => JSON.generate({
            :version => 1,
            :success => true,
            :id_token => EXECUTABLE_OIDC_TOKEN,
            :expiration_time => 999999999999,
          }),
          :stderr => "",
          :exit_status => 0
        },
        :expect_error => /The executable response is missing the token_type field./
      }
    ]
    before :example do
      ENV[Google::Auth::ExternalAccount::PluggableAuthCredentials::ENABLE_PLUGGABLE_ENV] = "1"
    end
    examples.each do |example|
      it example[:name] do
        command = fake_executable_returning(**example[:executable_return])
        credentials = PluggableAuthCredentials.new with_executable(example[:options], command)
        expect{credentials.retrieve_subject_token!}.to raise_error(example[:expect_error])
      end
    end
  end

  describe "test retrieve subject token success" do
    examples = [
      {
        :name => "id_token",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
        },
        :executable_return => {
          :stdout => JSON.generate(EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_ID_TOKEN),
          :stderr => "",
          :exit_status => 0
        },
        :expect_token => EXECUTABLE_OIDC_TOKEN
      },
      {
        :name => "jwt_token",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
        },
        :executable_return => {
          :stdout => JSON.generate(EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_JWT),
          :stderr => "",
          :exit_status => 0
        },
        :expect_token => EXECUTABLE_OIDC_TOKEN
      },
      {
        :name => "saml_token",
        :options => {
          :audience => AUDIENCE,
          :subject_token_type => SUBJECT_TOKEN_TYPE,
          :token_url => TOKEN_URL,
        },
        :executable_return => {
          :stdout => JSON.generate(EXECUTABLE_SUCCESSFUL_SAML_RESPONSE),
          :stderr => "",
          :exit_status => 0
        },
        :expect_token => EXECUTABLE_SAML_TOKEN
      },
    ]
    before :example do
      ENV[Google::Auth::ExternalAccount::PluggableAuthCredentials::ENABLE_PLUGGABLE_ENV] = "1"
    end
    examples.each do |example|
      it example[:name] do
        command = fake_executable_returning(**example[:executable_return])
        credentials = PluggableAuthCredentials.new with_executable(example[:options], command)
        expect(credentials.retrieve_subject_token!).to eql(example[:expect_token])
      end
    end
  end

  describe "test retrieve subject token executable lifecycle" do
    let(:options) { { audience: AUDIENCE, subject_token_type: SUBJECT_TOKEN_TYPE, token_url: TOKEN_URL } }
    # Below the 5 second minimum, which these specs lower to stay fast.
    let(:short_timeout_millis) { 500 }

    before :example do
      ENV[Google::Auth::ExternalAccount::PluggableAuthCredentials::ENABLE_PLUGGABLE_ENV] = "1"
    end

    # Runs script as an executable that overruns a short timeout, checks for the timeout
    # error, and returns the pid of the executable.
    def run_past_timeout script
      stub_const "Google::Auth::ExternalAccount::PluggableAuthCredentials::EXECUTABLE_TIMEOUT_MILLIS_LOWER_BOUND",
                 short_timeout_millis
      pids = record_executable_pids
      command = fake_executable_command script
      credentials = PluggableAuthCredentials.new with_executable(options, command, timeout_millis: short_timeout_millis)
      expect { credentials.retrieve_subject_token! }.to raise_error(
        Google::Auth::CredentialsError,
        "The executable failed to finish within the timeout specified (#{short_timeout_millis} ms)."
      )
      expect(pids.size).to eq(1)
      pids.first
    end

    it "returns the output unchanged while draining large stdout and stderr" do
      token = "t" * (256 * 1024)
      response = JSON.generate EXECUTABLE_SUCCESSFUL_OIDC_RESPONSE_ID_TOKEN.merge(id_token: token)
      command = fake_executable_command <<~SCRIPT
        $stdin.read # Returns at once, because stdin is closed for the executable.
        $stderr.write "e" * #{256 * 1024}
        $stdout.write #{response.dump}
      SCRIPT
      credentials = PluggableAuthCredentials.new with_executable(options, command)
      expect(credentials.retrieve_subject_token!).to eq(token)
    end

    # The timeout specs below rely on this: the pid that gets signaled is the executable's.
    it "starts the executable directly, not through a shell" do
      pids = record_executable_pids
      command = fake_executable_command <<~'SCRIPT'
        $stdout.write %({"version":1,"success":true,"token_type":"urn:ietf:params:oauth:token-type:id_token","id_token":"#{Process.pid}"})
      SCRIPT
      credentials = PluggableAuthCredentials.new with_executable(options, command)
      expect(credentials.retrieve_subject_token!).to eq(pids.first.to_s)
    end

    it "raises the same error as before for a non-zero exit" do
      command = fake_executable_returning stdout: "partial", stderr: "boom", exit_status: 3
      credentials = PluggableAuthCredentials.new with_executable(options, command)
      expect { credentials.retrieve_subject_token! }.to raise_error(
        Google::Auth::CredentialsError, "Executable exited with non-zero return code 3. Error: partial, boom"
      )
    end

    it "times out after timeout_millis milliseconds, not seconds" do
      started = Process.clock_gettime Process::CLOCK_MONOTONIC
      run_past_timeout "sleep 60"
      elapsed = Process.clock_gettime(Process::CLOCK_MONOTONIC) - started
      # Reading 500 as seconds, or waiting for the executable to exit, would take 60 seconds or more.
      expect(elapsed).to be_between(short_timeout_millis / 1000.0, 10)
    end

    it "terminates and reaps the executable and joins the reader threads after a timeout" do
      threads = Thread.list
      pid = run_past_timeout "sleep 60"
      expect(reaped?(pid)).to be(true)
      expect(Thread.list - threads).to be_empty
    end

    it "kills an executable that ignores TERM" do
      pid = run_past_timeout <<~SCRIPT
        begin
          Signal.trap "TERM", "IGNORE"
        rescue ArgumentError
          nil # Where TERM cannot be trapped, it is not sent either.
        end
        sleep 60
      SCRIPT
      expect(reaped?(pid)).to be(true)
    end
  end
end
