# Copyright 2023 Google, Inc.
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

# [START auth_cloud_idtoken_metadata_server]
require "googleauth"

##
# Uses the Google Cloud metadata server environment to create an identity token
# and add it to the HTTP request as part of an Authorization header.
#
# @param url [String] The url or target audience to obtain the ID token for 
#   (e.g. "http://www.example.com")
#
def auth_cloud_idtoken_metadata_server url:
  # Create the GCECredentials client.
  id_client = Google::Auth::GCECredentials.new target_audience: url

  # Get the ID token.
  # Once you've obtained the ID token, you can use it to make an authenticated call
  # to the target audience.
  id_client.fetch_access_token
  puts "Generated ID token."

  id_client.refresh!
end
# [END auth_cloud_idtoken_metadata_server]
