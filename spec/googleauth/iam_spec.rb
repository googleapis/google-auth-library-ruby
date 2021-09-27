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

require "googleauth/iam"

describe Google::Auth::IAMCredentials do
  IAMCredentials = Google::Auth::IAMCredentials
  let(:test_selector) { "the-test-selector" }
  let(:test_token) { "the-test-token" }
  let(:test_creds) { IAMCredentials.new test_selector, test_token }

  describe "#apply!" do
    it "should update the target hash with the iam values" do
      md = { foo: "bar" }
      test_creds.apply! md
      expect(md[IAMCredentials::SELECTOR_KEY]).to eq test_selector
      expect(md[IAMCredentials::TOKEN_KEY]).to eq test_token
      expect(md[:foo]).to eq "bar"
    end
  end

  describe "updater_proc" do
    it "should provide a proc that updates a hash with the iam values" do
      md = { foo: "bar" }
      the_proc = test_creds.updater_proc
      got = the_proc.call md
      expect(got[IAMCredentials::SELECTOR_KEY]).to eq test_selector
      expect(got[IAMCredentials::TOKEN_KEY]).to eq test_token
      expect(got[:foo]).to eq "bar"
    end
  end

  describe "#apply" do
    it "should not update the original hash with the iam values" do
      md = { foo: "bar" }
      test_creds.apply md
      expect(md[IAMCredentials::SELECTOR_KEY]).to be_nil
      expect(md[IAMCredentials::TOKEN_KEY]).to be_nil
      expect(md[:foo]).to eq "bar"
    end

    it "should return a with the iam values" do
      md = { foo: "bar" }
      got = test_creds.apply md
      expect(got[IAMCredentials::SELECTOR_KEY]).to eq test_selector
      expect(got[IAMCredentials::TOKEN_KEY]).to eq test_token
      expect(got[:foo]).to eq "bar"
    end
  end
end
