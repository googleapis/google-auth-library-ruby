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
require "fakefs/safe"

describe Google::Auth::ClientId do
  # A set of validity checks for a loaded ClientId.
  # This module can be included in any spec that defines `config`.
  client_id_load_checks = Module.new do
    def self.included spec
      # Define a module with some checks that a client ID is valid.
      # Memoize because this included hook gets called multiple times.
      valid_config_checks = @valid_config_checks ||= Module.new do
        extend Minitest::Spec::DSL
    
        it "should include a valid id" do
          _(client_id.id).must_equal "abc@example.com"
        end
    
        it "should include a valid secret" do
          _(client_id.secret).must_equal "notasecret"
        end
      end

      # Add these describe blocks to any spec class that includes the
      # client_id_load_checks module. Each describe block, in turn, includes
      # the valid_config_checks module defined above.
      spec.instance_eval do
        describe "loaded from hash" do
          let(:client_id) { Google::Auth::ClientId.from_hash config }
          include valid_config_checks
        end

        describe "loaded from file" do
          file_path = "/client_secrets.json"
          let :client_id do
            FakeFS do
              content = MultiJson.dump config
              File.write file_path, content
              Google::Auth::ClientId.from_file file_path
            end
          end
          include valid_config_checks
        end
      end
    end
  end

  describe "with web config" do
    let :config do
      {
        "web" => {
          "client_id"     => "abc@example.com",
          "client_secret" => "notasecret"
        }
      }
    end
    include client_id_load_checks
  end

  describe "with installed app config" do
    let :config do
      {
        "installed" => {
          "client_id"     => "abc@example.com",
          "client_secret" => "notasecret"
        }
      }
    end
    include client_id_load_checks
  end

  describe "with missing top level property" do
    let :config do
      {
        "notvalid" => {
          "client_id"     => "abc@example.com",
          "client_secret" => "notasecret"
        }
      }
    end

    it "should raise error" do
      error = assert_raises do
        Google::Auth::ClientId.from_hash config
      end
      assert_match(/Expected top level property/, error.message)
    end
  end

  describe "with missing client id" do
    let :config do
      {
        "web" => {
          "client_secret" => "notasecret"
        }
      }
    end

    it "should raise error" do
      error = assert_raises do
        Google::Auth::ClientId.from_hash config
      end
      assert_match(/Client id can not be nil/, error.message)
    end
  end

  describe "with missing client secret" do
    let :config do
      {
        "web" => {
          "client_id" => "abc@example.com"
        }
      }
    end

    it "should raise error" do
      error = assert_raises do
        Google::Auth::ClientId.from_hash config
      end
      assert_match(/Client secret can not be nil/, error.message)
    end
  end
end
