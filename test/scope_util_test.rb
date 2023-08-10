# Copyright 2023 Google LLC
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

require "helper"

describe Google::Auth::ScopeUtil do
  scope_util_normalization_specs = Module.new do
    extend Minitest::Spec::DSL
  
    let(:normalized) { Google::Auth::ScopeUtil.normalize source }
  
    it "normalizes the email scope" do
      _(normalized).must_include(
        "https://www.googleapis.com/auth/userinfo.email"
      )
      _(normalized).wont_include "email"
    end
  
    it "normalizes the profile scope" do
      _(normalized).must_include(
        "https://www.googleapis.com/auth/userinfo.profile"
      )
      _(normalized).wont_include "profile"
    end
  
    it "normalizes the openid scope" do
      _(normalized).must_include "https://www.googleapis.com/auth/plus.me"
      _(normalized).wont_include "openid"
    end
  
    it "leaves other other scopes as-is" do
      _(normalized).must_include "https://www.googleapis.com/auth/drive"
    end
  end

  describe "with scope as string" do
    let :source do
      "email profile openid https://www.googleapis.com/auth/drive"
    end
    include scope_util_normalization_specs
  end

  describe "with scope as Array" do
    let :source do
      ["email", "profile", "openid", "https://www.googleapis.com/auth/drive"]
    end
    include scope_util_normalization_specs
  end

  it "detects incorrect type" do
    assert_raises ArgumentError do
      Google::Auth::ScopeUtil.normalize :"https://www.googleapis.com/auth/userinfo.email"
    end
  end

  it "detects incorrect array element type" do
    assert_raises ArgumentError do
      Google::Auth::ScopeUtil.normalize [:"https://www.googleapis.com/auth/userinfo.email"]
    end
  end
end
