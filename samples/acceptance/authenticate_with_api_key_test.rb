# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require_relative "../authenticate_with_api_key"
require_relative "helper"
require "minitest/autorun"

describe "authenticate_with_api_key" do
  let(:api_key) { ENV["GOOGLE_API_KEY"] }
  let(:stdout_output) { capture_io { authenticate_with_api_key api_key } }

  skip "Requires real API key to run" do
    it "authenticates with API key" do
      # Skip the test if API key is not provided
      skip "No API key available" if api_key.nil? || api_key.empty?
      
      output = stdout_output[0]
      assert_includes output, "Text: Hello, world!"
      assert_includes output, "Sentiment:"
      assert_includes output, "Successfully authenticated using the API key"
    end
  end
end
