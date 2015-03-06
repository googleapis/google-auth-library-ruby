# Copyright 2015, Google Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer
# in the documentation and/or other materials provided with the
# distribution.
#     * Neither the name of Google Inc. nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

require 'memoist'
require 'rbconfig'

module Google
  # Module Auth provides classes that provide Google-specific authorization
  # used to access Google APIs.
  module Auth
    # CredentialsLoader contains the behaviour used to locate and find default
    # credentials files on the file system.
    module CredentialsLoader
      extend Memoist
      ENV_VAR = 'GOOGLE_APPLICATION_CREDENTIALS'
      NOT_FOUND_ERROR =
        "Unable to read the credential file specified by #{ENV_VAR}"
      WELL_KNOWN_PATH = 'gcloud/application_default_credentials.json'
      WELL_KNOWN_ERROR = 'Unable to read the default credential file'

      # determines if the current OS is windows
      def windows?
        RbConfig::CONFIG['host_os'] =~ /Windows|mswin/
      end
      memoize :windows?

      # Creates an instance from the path specified in an environment
      # variable.
      #
      # @param scope [string|array] the scope(s) to access
      def from_env(scope)
        return nil unless ENV.key?(ENV_VAR)
        path = ENV[ENV_VAR]
        fail 'file #{path} does not exist' unless File.exist?(path)
        File.open(path) do |f|
          return new(scope, f)
        end
      rescue StandardError => e
        raise "#{NOT_FOUND_ERROR}: #{e}"
      end

      # Creates an instance from a well known path.
      #
      # @param scope [string|array] the scope(s) to access
      def from_well_known_path(scope)
        home_var, base = windows? ? 'APPDATA' : 'HOME', WELL_KNOWN_PATH
        root = ENV[home_var].nil? ? '' : ENV[home_var]
        base = File.join('.config', base) unless windows?
        path = File.join(root, base)
        return nil unless File.exist?(path)
        File.open(path) do |f|
          return new(scope, f)
        end
      rescue StandardError => e
        raise "#{WELL_KNOWN_ERROR}: #{e}"
      end
    end
  end
end