# Copyright 2022 Google, Inc.
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

# [START auth_cloud_implicit_adc]
def authenticate_implicit_with_adc project_id:
  # The ID of your Google Cloud project
  # project_id = "your-google-cloud-project-id"

  ###
  # When interacting with Google Cloud Client libraries, the library can auto-detect the
  # credentials to use.
  # TODO(Developer):
  #   1. Before running this sample,
  #      set up ADC as described in https://cloud.google.com/docs/authentication/external/set-up-adc
  #   2. Replace the project variable.
  #   3. Make sure that the user account or service account that you are using
  #      has the required permissions. For this sample, you must have "storage.buckets.list".
  ###

  require "google/cloud/storage"

  # This sample demonstrates how to list buckets.
  # *NOTE*: Replace the client created below with the client required for your application.
  # Note that the credentials are not specified when constructing the client.
  # Hence, the client library will look for credentials using ADC.
  storage = Google::Cloud::Storage.new project_id: project_id
  buckets = storage.buckets
  puts "Buckets: "
  buckets.each do |bucket|
    puts bucket.name
  end
  puts "Plaintext: Listed all storage buckets."
end
# [END auth_cloud_implicit_adc]

authenticate_implicit_with_adc project_id: ARGV.shift if $PROGRAM_NAME == __FILE__
