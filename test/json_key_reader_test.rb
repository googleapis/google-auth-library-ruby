# Copyright 2025 Google LLC
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

require_relative "helper"
require "googleauth/json_key_reader"
require "stringio"
require "multi_json"

class DummyKeyReader
  include Google::Auth::JsonKeyReader
end

describe Google::Auth::JsonKeyReader do
  let(:dummy_reader) { DummyKeyReader.new }
  
  describe "#read_json_key" do
    it "reads all fields from a valid JSON key" do
      json_key_hash = {
        "private_key" => "dummy-key",
        "client_email" => "dummy@example.com",
        "project_id" => "dummy-project",
        "quota_project_id" => "quota-project",
        "universe_domain" => "googleapis.com"
      }
      
      json_key_io = StringIO.new(MultiJson.dump(json_key_hash))
      
      private_key, client_email, project_id, quota_project_id, universe_domain = 
        dummy_reader.read_json_key(json_key_io)
      
      _(private_key).must_equal "dummy-key"
      _(client_email).must_equal "dummy@example.com"
      _(project_id).must_equal "dummy-project"
      _(quota_project_id).must_equal "quota-project"
      _(universe_domain).must_equal "googleapis.com"
    end
    
    it "raises InitializationError when client_email is missing" do
      json_key_hash = {
        "private_key" => "dummy-key"
      }
      
      json_key_io = StringIO.new(MultiJson.dump(json_key_hash))
      
      error = assert_raises Google::Auth::InitializationError do
        dummy_reader.read_json_key(json_key_io)
      end
      
      _(error.message).must_equal "missing client_email"
    end
    
    it "raises InitializationError when private_key is missing" do
      json_key_hash = {
        "client_email" => "dummy@example.com"
      }
      
      json_key_io = StringIO.new(MultiJson.dump(json_key_hash))
      
      error = assert_raises Google::Auth::InitializationError do
        dummy_reader.read_json_key(json_key_io)
      end
      
      _(error.message).must_equal "missing private_key"
    end
  end
end