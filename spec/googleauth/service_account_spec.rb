# Copyright 2015, Google Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer
# in the documentation and/or other materials provided with the
# distribution.
#     * Neither the name of Google Inc. nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

spec_dir = File.expand_path(File.join(File.dirname(__FILE__)))
$LOAD_PATH.unshift(spec_dir)
$LOAD_PATH.uniq!

require 'apply_auth_examples'
require 'fileutils'
require 'googleauth/service_account'
require 'jwt'
require 'multi_json'
require 'openssl'
require 'spec_helper'
require 'tmpdir'

describe Google::Auth::ServiceAccountCredentials do
  ServiceAccountCredentials = Google::Auth::ServiceAccountCredentials

  before(:example) do
    @key = OpenSSL::PKey::RSA.new(2048)
    @client = ServiceAccountCredentials.new(
        'https://www.googleapis.com/auth/userinfo.profile',
        StringIO.new(cred_json_text))
  end

  def make_auth_stubs(opts = {})
    access_token = opts[:access_token] || ''
    Faraday::Adapter::Test::Stubs.new do |stub|
      stub.post('/oauth2/v3/token') do |env|
        params = Addressable::URI.form_unencode(env[:body])
        _claim, _header = JWT.decode(params.assoc('assertion').last,
                                     @key.public_key)
        want = ['grant_type', 'urn:ietf:params:oauth:grant-type:jwt-bearer']
        expect(params.assoc('grant_type')).to eq(want)
        build_access_token_json(access_token)
      end
    end
  end

  def cred_json_text
    cred_json = {
      private_key_id: 'a_private_key_id',
      private_key: @key.to_pem,
      client_email: 'app@developer.gserviceaccount.com',
      client_id: 'app.apps.googleusercontent.com',
      type: 'service_account'
    }
    MultiJson.dump(cred_json)
  end

  it_behaves_like 'apply/apply! are OK'

  describe '#from_env' do
    before(:example) do
      @var_name = ServiceAccountCredentials::ENV_VAR
      @orig = ENV[@var_name]
      @scope = 'https://www.googleapis.com/auth/userinfo.profile'
    end

    after(:example) do
      ENV[@var_name] = @orig unless @orig.nil?
    end

    it 'returns nil if the GOOGLE_APPLICATION_CREDENTIALS is unset' do
      ENV.delete(@var_name) unless ENV[@var_name].nil?
      expect(ServiceAccountCredentials.from_env(@scope)).to be_nil
    end

    it 'fails if the GOOGLE_APPLICATION_CREDENTIALS path does not exist' do
      ENV.delete(@var_name) unless ENV[@var_name].nil?
      expect(ServiceAccountCredentials.from_env(@scope)).to be_nil
      Dir.mktmpdir do |dir|
        key_path = File.join(dir, 'does-not-exist')
        ENV[@var_name] = key_path
        expect { sac.from_env(@scope) }.to raise_error
      end
    end

    it 'succeeds when the GOOGLE_APPLICATION_CREDENTIALS file is valid' do
      sac = ServiceAccountCredentials  # shortens name
      Dir.mktmpdir do |dir|
        key_path = File.join(dir, 'my_cert_file')
        FileUtils.mkdir_p(File.dirname(key_path))
        File.write(key_path, cred_json_text)
        ENV[@var_name] = key_path
        expect(sac.from_env(@scope)).to_not be_nil
      end
    end
  end

  describe '#from_well_known_path' do
    before(:example) do
      @home = ENV['HOME']
      @scope = 'https://www.googleapis.com/auth/userinfo.profile'
    end

    after(:example) do
      ENV['HOME'] = @home unless @home == ENV['HOME']
    end

    it 'is nil if no file exists' do
      ENV['HOME'] = File.dirname(__FILE__)
      expect(ServiceAccountCredentials.from_well_known_path(@scope)).to be_nil
    end

    it 'successfully loads the file when it is present' do
      sac = ServiceAccountCredentials  # shortens name
      Dir.mktmpdir do |dir|
        key_path = File.join(dir, '.config', sac::WELL_KNOWN_PATH)
        FileUtils.mkdir_p(File.dirname(key_path))
        File.write(key_path, cred_json_text)
        ENV['HOME'] = dir
        expect(sac.from_well_known_path(@scope)).to_not be_nil
      end
    end
  end
end
