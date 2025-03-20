# frozen_string_literal: true

require "signet/oauth_2/client"

# Copyright 2025 Google LLC
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
    # Error mixin module for Google Auth errors
    # All Google Auth errors should include this module
    #
    module Error; end

    ##
    # Mixin module that contains detailed error information
    # typically this is available if credentials initialization
    # succeeds and credentials object is valid
    #
    module DetailedError
      include Error

      # The type of the credentials that the error was originated from
      # @return [String, nil] The class name of the credential that raised the error
      attr_reader :credential_type_name

      # The principal for the authentication flow. Typically obtained from credentials
      # @return [String, Symbol, nil] The principal identifier associated with the credentials
      attr_reader :principal

      # All details passed in the options hash when creating the error
      # @return [Hash] Additional details about the error
      attr_reader :details

      # Hacks
      def self.included base
        base.extend ClassMethods
      end

      # Class methods to be added to including classes
      module ClassMethods
        # Creates a new error with detailed information
        # @param message [String] The error message
        # @param options [Hash] The options to create the error with
        # @option options [String] :credential_type_name The credential type that raised the error
        # @option options [String, Symbol] :principal The principal for the authentication flow
        # @return [Error] The new error with details
        def with_details message, **options
          new(message).tap do |error|
            # Store each option as an instance variable
            options.each do |key, value|
              error.instance_variable_set :"@#{key}", value
            end
            # Also store the entire options hash for convenience
            error.instance_variable_set :@details, options
          end
        end
      end
    end

    ##
    # @private
    # Error raised during Credentials initialization.
    # All new code should use this instead of ArgumentError during initializtion.
    #
    # The YARD documentation describing raising this error should use `Google::Auth::Error`,
    # e.g. `@raise [Google::Auth::Error]`
    #
    class InitializationError < StandardError
      include Error
    end

    ##
    # @private
    # Generic error raised during operation of Credentials
    # This should be used for all purposes not covered by other errors.
    #
    # The YARD documentation describing raising this error should use `Google::Auth::DetailedError`,
    # e.g. `@raise [Google::Auth::DetailedError]`
    #
    class CredentialsError < StandardError
      include DetailedError
    end

    ##
    # An error indicating the remote server refused to authorize the client.
    # Maintains backward compatibility with Signet
    # This is OK to use in the new code, even if the class is not Signet-based,
    # as long as there is an exchange with a remote server.
    #
    # For the new usages, the YARD documentation describing raising this error
    # should use `Google::Auth::DetailedError`, e.g. `@raise [Google::Auth::DetailedError]`
    # The old usages refer to `AuthorizationError` for backwards compatibility
    #
    class AuthorizationError < Signet::AuthorizationError
      include DetailedError
    end

    ##
    # An error indicating that the server sent an unexpected http status
    # Maintains backward compatibility with Signet
    # Should not be used in the new code. Use AuthorizationError instead.
    #
    class UnexpectedStatusError < Signet::UnexpectedStatusError
      include DetailedError
    end

    ##
    # An error indicating the client failed to parse a value.
    # Maintains backward compatibility with Signet
    # Should not be used in the new code.
    #
    class ParseError < Signet::ParseError
      include DetailedError
    end
  end
end
