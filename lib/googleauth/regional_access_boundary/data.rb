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

module Google
  module Auth
    module RegionalAccessBoundary
      # RegionalAccessBoundaryData holds the encoded locations for Regional Access Boundary.
      #
      # @private
      class RegionalAccessBoundaryData
        # @return [String] the base64-encoded allowed locations payload.
        attr_reader :encoded_locations

        # @param encoded_locations [String] the base64-encoded allowed locations payload.
        def initialize encoded_locations
          @encoded_locations = encoded_locations
        end
      end
    end
  end
end
