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

require 'googleauth'
require 'googleauth/user_authorizer'
require 'uri'
require 'multi_json'
require 'spec_helper'

describe Google::Auth::InstalledAppUserAuthorizer do
  include TestHelpers

  let(:client_id) { Google::Auth::ClientId.new('testclient', 'notasecret') }
  let(:scope) { %w(email profile) }
  let(:token_store) { DummyTokenStore.new }
  let(:token_json) do
    MultiJson.dump('access_token' => '1/abc123',
                   'token_type' => 'Bearer',
                   'expires_in' => 3600)
  end

  before(:example) do
    token_store.store('user2@example.com', token_json)
  end

  before(:example) do
    stub_request(:post, 'https://www.googleapis.com/oauth2/v3/token').to_return(
      body: token_json,
      status: 200,
      headers: { 'Content-Type' => 'application/json' })
  end

  let(:authorizer) do
    Google::Auth::InstalledAppUserAuthorizer.new(client_id, scope, token_store)
  end

  context 'when invoked with callback' do
    context 'with no saved credentials' do
      it 'should prompt for authorization' do
        expect do |b|
          authorizer.get_credentials('user@example.com') do |url|
            b.to_proc.call(url)
            'code'
          end
        end.to yield_with_args(%r{https://accounts.google.com/.*})
      end

      it 'should return valid credentials' do
        credentials = authorizer.get_credentials('user@example.com') do |_url|
          'code'
        end
        expect(credentials).to be_instance_of(
          Google::Auth::UserRefreshCredentials)
      end
    end
  end

  context 'when invoked without callback' do
    context 'with no saved credentials' do
      let(:server) do
        double('webrick', start: nil, stop: nil, shutdown: nil)
      end

      before(:example) do
        allow(authorizer).to receive(:create_server).and_return(server)
        expect(server).to receive(:mount_proc) do |_url, &proc|
          @proc = proc
        end
        expect(server).to receive(:start) do
          request = double('request', query: { 'code' => 'authcode' })
          response = double('response')
          expect(response).to receive(:status=).with(202)
          expect(response).to receive(:body=).with(String)
          @proc.call(request, response)
        end
      end

      let(:credentials) { authorizer.get_credentials('user@example.com') }

      it 'should prompt for authorization' do
        expect(Launchy).to receive(:open).with(
          %r{https://accounts.google.com/.*})
        credentials
      end

      it 'should return valid credentials' do
        expect(Launchy).to receive(:open).with(
          %r{https://accounts.google.com/.*})
        expect(credentials).to be_instance_of(
          Google::Auth::UserRefreshCredentials)
      end
    end

    it 'should return saved credentials' do
      credentials = authorizer.get_credentials('user2@example.com')
      expect(credentials).to be_instance_of(
        Google::Auth::UserRefreshCredentials)
    end
  end
end
