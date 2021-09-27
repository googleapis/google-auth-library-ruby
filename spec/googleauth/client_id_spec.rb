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

require "spec_helper"
require "fakefs/safe"
require "googleauth"

describe Google::Auth::ClientId do
  shared_examples "it has a valid config" do
    it "should include a valid id" do
      expect(client_id.id).to eql "abc@example.com"
    end

    it "should include a valid secret" do
      expect(client_id.secret).to eql "notasecret"
    end
  end

  shared_examples "it can successfully load client_id" do
    context "loaded from hash" do
      let(:client_id) { Google::Auth::ClientId.from_hash config }

      it_behaves_like "it has a valid config"
    end

    context "loaded from file" do
      file_path = "/client_secrets.json"

      let :client_id do
        FakeFS do
          content = MultiJson.dump config
          File.write file_path, content
          Google::Auth::ClientId.from_file file_path
        end
      end

      it_behaves_like "it has a valid config"
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
    it_behaves_like "it can successfully load client_id"
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
    it_behaves_like "it can successfully load client_id"
  end

  context "with missing top level property" do
    let :config do
      {
        "notvalid" => {
          "client_id"     => "abc@example.com",
          "client_secret" => "notasecret"
        }
      }
    end

    it "should raise error" do
      expect { Google::Auth::ClientId.from_hash config }.to raise_error(
        /Expected top level property/
      )
    end
  end

  context "with missing client id" do
    let :config do
      {
        "web" => {
          "client_secret" => "notasecret"
        }
      }
    end

    it "should raise error" do
      expect { Google::Auth::ClientId.from_hash config }.to raise_error(
        /Client id can not be nil/
      )
    end
  end

  context "with missing client secret" do
    let :config do
      {
        "web" => {
          "client_id" => "abc@example.com"
        }
      }
    end

    it "should raise error" do
      expect { Google::Auth::ClientId.from_hash config }.to raise_error(
        /Client secret can not be nil/
      )
    end
  end

  context "with cloud sdk credentials" do
    let :config do
      {
        "web" => {
          "client_id"     => Google::Auth::CredentialsLoader::CLOUD_SDK_CLIENT_ID,
          "client_secret" => "notasecret"
        }
      }
    end

    it "should raise warning" do
      expect { Google::Auth::ClientId.from_hash config }.to output(
        Google::Auth::CredentialsLoader::CLOUD_SDK_CREDENTIALS_WARNING + "\n"
      ).to_stderr
    end
  end
end
