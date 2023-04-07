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

require "time"
require "uri"
require "googleauth/credentials_loader"
require "googleauth/external_account/aws_credentials"

module Google
  # Module Auth provides classes that provide Google-specific authorization
  # used to access Google APIs.
  module Auth
    # Authenticates requests using External Account credentials, such
    # as those provided by the AWS provider.
    module ExternalAccount
      # Provides an entrypoint for all Exernal Account credential classes.
      class Credentials
        # The subject token type used for AWS external_account credentials.
        AWS_SUBJECT_TOKEN_TYPE = "urn:ietf:params:aws:token-type:aws4_request".freeze
        AWS_SUBJECT_TOKEN_INVALID = "aws is the only currently supported external account type".freeze

        # Create a ExternalAccount::Credentials
        #
        # @param json_key_io [IO] an IO from which the JSON key can be read
        # @param scope [String,Array,nil] the scope(s) to access
        def self.make_creds options = {}
          json_key_io, scope = options.values_at :json_key_io, :scope

          raise "A json file is required for external account credentials." unless json_key_io
          user_creds = read_json_key json_key_io

          # TODO: check for other External Account Credential types. Currently only AWS is supported.
          raise AWS_SUBJECT_TOKEN_INVALID unless user_creds["subject_token_type"] == AWS_SUBJECT_TOKEN_TYPE

          Google::Auth::ExternalAccount::AwsCredentials.new(
            audience: user_creds["audience"],
            scope: scope,
            subject_token_type: user_creds["subject_token_type"],
            token_url: user_creds["token_url"],
            credential_source: user_creds["credential_source"],
            service_account_impersonation_url: user_creds["service_account_impersonation_url"]
          )
        end

        # Reads the required fields from the JSON.
        def self.read_json_key json_key_io
          json_key = MultiJson.load json_key_io.read
          wanted = [
            "audience", "subject_token_type", "token_url", "credential_source"
          ]
          wanted.each do |key|
            raise "the json is missing the #{key} field" unless json_key.key? key
          end
          json_key
        end
      end
    end
  end
end
