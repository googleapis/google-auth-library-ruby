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

require "minitest/autorun"

class AuthCloudIdtokenMetadataServer
  sample_file = File.read "#{__dir__}/../auth_cloud_idtoken_metadata_server.rb"
  eval sample_file
end

require "googleauth"

describe "Get an ID token from the metadata server" do
  let(:url) { "https://pubsub.googleapis.com/" }

  it "get_an_id_token" do
    assert_output "Generated ID token." do
      AuthCloudIdtokenMetadataServer.new.auth_cloud_idtoken_metadata_server url: url
    end
  end
end
