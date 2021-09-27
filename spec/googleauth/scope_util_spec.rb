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

require "googleauth/scope_util"

describe Google::Auth::ScopeUtil do
  shared_examples "normalizes scopes" do
    let(:normalized) { Google::Auth::ScopeUtil.normalize source }

    it "normalizes the email scope" do
      expect(normalized).to include(
        "https://www.googleapis.com/auth/userinfo.email"
      )
      expect(normalized).to_not include "email"
    end

    it "normalizes the profile scope" do
      expect(normalized).to include(
        "https://www.googleapis.com/auth/userinfo.profile"
      )
      expect(normalized).to_not include "profile"
    end

    it "normalizes the openid scope" do
      expect(normalized).to include "https://www.googleapis.com/auth/plus.me"
      expect(normalized).to_not include "openid"
    end

    it "leaves other other scopes as-is" do
      expect(normalized).to include "https://www.googleapis.com/auth/drive"
    end
  end

  context "with scope as string" do
    let :source do
      "email profile openid https://www.googleapis.com/auth/drive"
    end
    it_behaves_like "normalizes scopes"
  end

  context "with scope as Array" do
    let :source do
      %w[email profile openid https://www.googleapis.com/auth/drive]
    end
    it_behaves_like "normalizes scopes"
  end
end
