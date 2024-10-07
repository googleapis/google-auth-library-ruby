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
require "spec_helper"

shared_examples "apply/apply! are OK" do
  let(:auth_key) { :authorization }

  # tests that use these examples need to define
  #
  # @client which should be an auth client
  #
  # @make_auth_stubs, which should stub out the expected http behaviour of the
  # auth client
  describe "#fetch_access_token" do
    let(:token) { "1/abcdef1234567890" }
    let :access_stub do
      make_auth_stubs access_token: token
    end
    let :id_stub do
      make_auth_stubs id_token: token
    end

    it "should set access_token to the fetched value" do
      access_stub
      @client.fetch_access_token!
      expect(@client.access_token).to eq(token)
      expect(access_stub).to have_been_requested
    end

    it "should set id_token to the fetched value" do
      skip unless @id_client
      id_stub
      @id_client.fetch_access_token!
      expect(@id_client.id_token).to eq(token)
      expect(id_stub).to have_been_requested
    end

    it "should notify refresh listeners after updating" do
      access_stub
      expect do |b|
        @client.on_refresh(&b)
        @client.fetch_access_token!
      end.to yield_with_args(have_attributes(
                               access_token: "1/abcdef1234567890"
                             ))
      expect(access_stub).to have_been_requested
    end

    it "should log when a logger is set" do
      access_stub
      io = StringIO.new
      @client.logger = Logger.new io
      @client.fetch_access_token!
      expect(io.string).to include "INFO -- : Requesting access token from"
    end

    it "should not log to stdout when a logger is not set" do
      access_stub
      @client.logger = nil
      expect { @client.fetch_access_token! }.to_not output.to_stdout
    end

    it "should not log to stderr when a logger is not set" do
      access_stub
      @client.logger = nil
      expect { @client.fetch_access_token! }.to_not output.to_stderr
    end
  end

  describe "#apply!" do
    it "should update the target hash with fetched access token" do
      token = "1/abcdef1234567890"
      stub = make_auth_stubs access_token: token

      md = { foo: "bar" }
      @client.apply! md
      want = { :foo => "bar", auth_key => "Bearer #{token}" }
      expect(md).to eq(want)
      expect(stub).to have_been_requested
    end

    it "should update the target hash with fetched ID token" do
      skip unless @id_client
      token = "1/abcdef1234567890"
      stub = make_auth_stubs id_token: token

      md = { foo: "bar" }
      @id_client.apply! md
      want = { :foo => "bar", auth_key => "Bearer #{token}" }
      expect(md).to eq(want)
      expect(stub).to have_been_requested
    end
  end

  describe "updater_proc" do
    it "should provide a proc that updates a hash with the access token" do
      token = "1/abcdef1234567890"
      stub = make_auth_stubs access_token: token
      md = { foo: "bar" }
      the_proc = @client.updater_proc
      got = the_proc.call md
      want = { :foo => "bar", auth_key => "Bearer #{token}" }
      expect(got).to eq(want)
      expect(stub).to have_been_requested
    end
  end

  describe "#apply" do
    it "should not update the original hash with the access token" do
      token = "1/abcdef1234567890"
      stub = make_auth_stubs access_token: token

      md = { foo: "bar" }
      @client.apply md
      want = { foo: "bar" }
      expect(md).to eq(want)
      expect(stub).to have_been_requested
    end

    it "should add the token to the returned hash" do
      token = "1/abcdef1234567890"
      stub = make_auth_stubs access_token: token

      md = { foo: "bar" }
      got = @client.apply md
      want = { :foo => "bar", auth_key => "Bearer #{token}" }
      expect(got).to eq(want)
      expect(stub).to have_been_requested
    end

    it "should not fetch a new token if the current is not expired" do
      token = "1/abcdef1234567890"
      stub = make_auth_stubs access_token: token

      n = 5 # arbitrary
      n.times do |_t|
        md = { foo: "bar" }
        got = @client.apply md
        want = { :foo => "bar", auth_key => "Bearer #{token}" }
        expect(got).to eq(want)
      end
      expect(stub).to have_been_requested
    end

    it "should fetch a new token if the current one is expired" do
      token1 = "1/abcdef1234567890"
      token2 = "2/abcdef1234567891"

      [token1, token2].each do |t|
        make_auth_stubs access_token: t
        md = { foo: "bar" }
        got = @client.apply md
        want = { :foo => "bar", auth_key => "Bearer #{t}" }
        expect(got).to eq(want)
        @client.expires_at -= 3601 # default is to expire in 1hr
        Google::Cloud.env.compute_metadata.cache.expire_all!
      end
    end
  end
end
