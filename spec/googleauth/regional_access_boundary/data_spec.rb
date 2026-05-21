# Copyright 2026 Google LLC
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

require "spec_helper"
require "googleauth"
require "googleauth/regional_access_boundary/data"

describe Google::Auth::RegionalAccessBoundary::RegionalAccessBoundaryData do
  describe "#initialize" do
    it "stores encoded locations" do
      data = described_class.new "0xABC"
      expect(data.encoded_locations).to eq "0xABC"
    end
  end
end
