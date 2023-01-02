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

require_relative "helper"
require_relative "../auth_cloud_idtoken_metadata_server"

require "googleauth"

describe "Get an ID token from the metadata server" do
  let(:url) { "https://pubsub.googleapis.com/" }

  describe "id_token" do
    it "get_an_id_token" do
      out, _err = capture_io do
        auth_cloud_idtoken_metadata_server url: url
      end

      assert_includes out, "Generated ID token."
    end
  end
end
