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

require_relative "helper"
require_relative "../authenticate_implicit_with_adc"

require "google/cloud/storage"

describe "Authenticate Implicit with ADC Samples" do
  let(:storage_client) { Google::Cloud::Storage.new }

  describe "buckets" do
    it "list_buckets" do
      # list_buckets
      out, _err = capture_io do
        authenticate_implicit_with_adc project_id: storage_client.project
      end

      assert_includes out, "Listed all storage buckets."
    end
  end
end
