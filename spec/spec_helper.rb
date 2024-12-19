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

spec_dir = __dir__
root_dir = File.expand_path File.join(spec_dir, "..")
lib_dir = File.expand_path File.join(root_dir, "lib")

$LOAD_PATH.unshift spec_dir
$LOAD_PATH.unshift lib_dir
$LOAD_PATH.uniq!

require "faraday"
require "rspec"
require "logging"
require "rspec/logging_helper"
require "webmock/rspec"
require "multi_json"
require "google/cloud/env"

# Preload adapter to work around Rubinius error with FakeFS
MultiJson.use :json_gem

# Allow Faraday to support test stubs
Faraday::Adapter.lookup_middleware :test

# Configure RSpec to capture log messages for each test. The output from the
# logs will be stored in the @log_output variable. It is a StringIO instance.
RSpec.configure do |config|
  include RSpec::LoggingHelper
  config.capture_log_messages
  config.include WebMock::API
  config.filter_run focus: true
  config.run_all_when_everything_filtered = true
end

module TestHelpers
  include WebMock::API
  include WebMock::Matchers
end

class DummyTokenStore
  def initialize
    @tokens = {}
  end

  def load id
    @tokens[id]
  end

  def store id, token
    @tokens[id] = token
  end

  def delete id
    @tokens.delete id
  end
end
