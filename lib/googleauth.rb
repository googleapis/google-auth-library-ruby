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

require 'googleauth/application_default'
require 'googleauth/client_id'
require 'googleauth/credentials'
require 'googleauth/default_credentials'
require 'googleauth/user_authorizer'
require 'googleauth/web_user_authorizer'

module Google
  # Module Auth provides classes that provide Google-specific authorization
  # used to access Google APIs.
  module Auth
    # rubocop:disable MethodDefParentheses

    # On March 31, 2019, set supported version to 2.4 and recommended to 2.6.
    # Thereafter, follow the MRI support schedule: supported means non-EOL,
    # and recommended means in normal (rather than security) maintenance.
    # See https://www.ruby-lang.org/en/downloads/branches/
    ##
    # Minimum "supported" Ruby version (non-EOL)
    # @private
    #
    SUPPORTED_VERSION_THRESHOLD = '1.9'.freeze
    ##
    # Minimum "recommended" Ruby version (normal maintenance)
    # @private
    #
    RECOMMENDED_VERSION_THRESHOLD = '2.4'.freeze
    ##
    # Check Ruby version and emit a warning if it is old
    # @private
    #
    def self.warn_on_old_ruby_version
      return if ENV['GOOGLE_CLOUD_SUPPRESS_RUBY_WARNINGS']
      cur_version = Gem::Version.new RUBY_VERSION
      if cur_version < Gem::Version.new(SUPPORTED_VERSION_THRESHOLD)
        warn_unsupported_ruby cur_version, RECOMMENDED_VERSION_THRESHOLD
      elsif cur_version < Gem::Version.new(RECOMMENDED_VERSION_THRESHOLD)
        warn_nonrecommended_ruby cur_version, RECOMMENDED_VERSION_THRESHOLD
      end
    rescue ArgumentError
      warn 'Unable to determine current Ruby version.'
    end

    ##
    # Print a warning for an EOL version of Ruby
    # @private
    #
    def self.warn_unsupported_ruby cur_version, recommended_version
      warn "WARNING: You are running Ruby #{cur_version}, which has reached" \
        ' end-of-life and is no longer supported by Ruby Core.'
      warn 'The Google Cloud API clients work best on supported versions of' \
        ' Ruby. It is strongly recommended that you upgrade to Ruby' \
        " #{recommended_version} or later."
      warn 'See https://www.ruby-lang.org/en/downloads/branches/ for more' \
        ' info on the Ruby maintenance schedule.'
      warn 'To suppress this message, set the' \
        ' GOOGLE_CLOUD_SUPPRESS_RUBY_WARNINGS environment variable.'
    end

    ##
    # Print a warning for a supported but nearing EOL version of Ruby
    # @private
    #
    def self.warn_nonrecommended_ruby cur_version, recommended_version
      warn "WARNING: You are running Ruby #{cur_version}, which is nearing" \
        ' end-of-life.'
      warn 'The Google Cloud API clients work best on supported versions of' \
        " Ruby. Consider upgrading to Ruby #{recommended_version} or later."
      warn 'See https://www.ruby-lang.org/en/downloads/branches/ for more' \
        ' info on the Ruby maintenance schedule.'
      warn 'To suppress this message, set the' \
        ' GOOGLE_CLOUD_SUPPRESS_RUBY_WARNINGS environment variable.'
    end
    # rubocop:enable MethodDefParentheses
  end
end

Google::Auth.warn_on_old_ruby_version
