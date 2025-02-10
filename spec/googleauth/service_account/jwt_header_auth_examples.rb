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

require "spec_helper"

shared_examples "jwt header auth" do |aud="https://www.googleapis.com/myservice"|
  context "when jwt_aud_uri is present" do
    let(:test_uri) { aud }
    let(:test_scope) { "scope/1 scope/2" }
    let(:auth_prefix) { "Bearer " }
    let(:auth_key) { ServiceAccountJwtHeaderCredentials::AUTH_METADATA_KEY }
    let(:jwt_uri_key) { ServiceAccountJwtHeaderCredentials::JWT_AUD_URI_KEY }

    def expect_is_encoded_jwt hdr
      expect(hdr).to_not be_nil
      expect(hdr.start_with?(auth_prefix)).to be true
      authorization = hdr[auth_prefix.length..-1]
      payload, = JWT.decode authorization, @key.public_key, true, algorithm: "RS256"

      expect(payload["aud"]).to eq(test_uri) if not test_uri.nil?
      expect(payload["scope"]).to eq(test_scope) if test_uri.nil?
      expect(payload["iss"]).to eq(client_email)
    end

    describe "#apply!" do
      it "should update the target hash with a jwt token" do
        md = { foo: "bar" }
        md[jwt_uri_key] = test_uri if test_uri
        @client.apply! md
        auth_header = md[auth_key]
        expect_is_encoded_jwt auth_header
        expect(md[jwt_uri_key]).to be_nil
      end
    end

    describe "updater_proc" do
      it "should provide a proc that updates a hash with a jwt token" do
        md = { foo: "bar" }
        md[jwt_uri_key] = test_uri if test_uri
        the_proc = @client.updater_proc
        got = the_proc.call md
        auth_header = got[auth_key]
        expect_is_encoded_jwt auth_header
        expect(got[jwt_uri_key]).to be_nil
        expect(md[jwt_uri_key]).to_not be_nil if test_uri
      end
    end

    describe "#apply" do
      it "should not update the original hash with a jwt token" do
        md = { foo: "bar" }
        md[jwt_uri_key] = test_uri if test_uri
        the_proc = @client.updater_proc
        got = the_proc.call md
        auth_header = md[auth_key]
        expect(auth_header).to be_nil
        expect(got[jwt_uri_key]).to be_nil
        expect(md[jwt_uri_key]).to_not be_nil if test_uri
      end

      it "should add a jwt token to the returned hash" do
        md = { foo: "bar" }
        md[jwt_uri_key] = test_uri if test_uri
        got = @client.apply md
        auth_header = got[auth_key]
        expect_is_encoded_jwt auth_header
      end
    end

    describe "#needs_access_token?" do
      it "should always return false" do
        expect(@client.needs_access_token?).to eq(false)
      end
    end
  end
end
