# Copyright 2022 Google LLC
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

require "google/cloud/storage"

require_relative "helper"

describe "Authenticate Implicit with ADC Samples" do
  let(:storage_client) { Google::Cloud::Storage.new }

  it "list_buckets" do
    # list_buckets
    sample = SampleLoader.load "authenticate_implicit_with_adc.rb"

    assert_output(/Plaintext: Listed all storage buckets./) do
      sample.run project_id: storage_client.project
    end
  end
end
