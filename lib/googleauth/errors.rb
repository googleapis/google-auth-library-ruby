# frozen_string_literal: true

# Copyright 2024 Google LLC
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
    ##
    # Base exception class for Google-specific authorization errors.
    #
    class Error < StandardError; end

    ##
    # Failed to obtain an application's identity for user authorization flows.
    #
    class ClientIdError < Error; end

    ##
    # Failed to obtain credentials.
    #
    class CredentialsError < Error; end

    ##
    # Failed to request authorization.
    #
    class AuthorizerError < Error; end

    ##
    # Failed to obtain a token.
    #
    class TokenError < Error; end
  end
end
