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
require "googleauth/stores/redis_token_store"
require "spec_helper"
require "fakeredis/rspec"
require "googleauth/stores/store_examples"

describe Google::Auth::Stores::RedisTokenStore do
  let :redis do
    Redis.new
  end

  let :store do
    Google::Auth::Stores::RedisTokenStore.new redis: redis
  end

  it_behaves_like "token store"
end
