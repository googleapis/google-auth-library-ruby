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

require "googleauth"
require "googleauth/stores/file_token_store"
require "spec_helper"
require "fakefs/safe"
require "fakefs/spec_helpers"
require "googleauth/stores/store_examples"

module FakeFS
  class File
    # FakeFS doesn't implement. And since we don't need to actually lock,
    # just stub out...
    def flock *; end
  end
end

describe Google::Auth::Stores::FileTokenStore do
  include FakeFS::SpecHelpers

  let :store do
    Google::Auth::Stores::FileTokenStore.new file: "/tokens.yaml"
  end

  it_behaves_like "token store"
end
