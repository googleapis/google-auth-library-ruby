# Copyright 2017, Google Inc.
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

require 'forwardable'
require 'json'
require 'signet/oauth_2/client'

require 'googleauth/default_credentials'

module Google
  module Auth
    # This class is intended to be inherited by API-specific classes
    # which overrides the SCOPE constant.
    class Credentials
      TOKEN_CREDENTIAL_URI = 'https://accounts.google.com/o/oauth2/token'.freeze
      AUDIENCE = 'https://accounts.google.com/o/oauth2/token'.freeze
      SCOPE = [].freeze
      PATH_ENV_VARS = [].freeze
      JSON_ENV_VARS = [].freeze
      DEFAULT_PATHS = [].freeze

      attr_accessor :client

      # Delegate client methods to the client object.
      extend Forwardable
      def_delegators :@client,
                     :token_credential_uri, :audience,
                     :scope, :issuer, :signing_key, :updater_proc

      def initialize(keyfile, scope: nil)
        verify_keyfile_provided! keyfile
        if keyfile.is_a? Signet::OAuth2::Client
          @client = keyfile
        elsif keyfile.is_a? Hash
          hash = stringify_hash_keys keyfile
          hash['scope'] ||= scope
          @client = init_client hash
        else
          verify_keyfile_exists! keyfile
          json = JSON.parse ::File.read(keyfile)
          json['scope'] ||= scope
          @client = init_client json
        end
        @client.fetch_access_token!
      end

      # Returns the default credentials.
      def self.default(scope: nil)
        # First try to find keyfile file from environment variables.
        self::PATH_ENV_VARS.map(&method(:env))
                           .compact
                           .select(&method(:path))
                           .each do |file|
          return new file, scope: scope
        end
        # Second try to find keyfile json from environment variables.
        self::JSON_ENV_VARS.map(&method(:json)).compact.each do |hash|
          return new hash, scope: scope
        end
        # Third try to find keyfile file from known file paths.
        self::DEFAULT_PATHS.select(&method(:path)).each do |file|
          return new file, scope: scope
        end
        # Finally get instantiated client from Google::Auth.
        scope ||= self::SCOPE
        client = Google::Auth.get_application_default scope
        new client
      end

      def self.env(v)
        ENV[v]
      end

      def self.json(v)
        unless ENV[v].nil?
          begin
            JSON.parse ENV[v]
          rescue
            nil
          end
        end
      end

      def self.path(p)
        ::File.file? p
      end

      protected

      # Verify that the keyfile argument is provided.
      def verify_keyfile_provided!(keyfile)
        return unless keyfile.nil?
        raise 'The keyfile passed to Google::Auth::Credentials.new was nil.'
      end

      # Verify that the keyfile argument is a file.
      def verify_keyfile_exists!(keyfile)
        exists = ::File.file? keyfile
        raise "The keyfile '#{keyfile}' is not a valid file." unless exists
      end

      # Initializes the Signet client.
      def init_client(keyfile)
        client_opts = client_options keyfile
        Signet::OAuth2::Client.new client_opts
      end

      # returns a new Hash with string keys instead of symbol keys.
      def stringify_hash_keys(hash)
        Hash[hash.map { |k, v| [k.to_s, v] }]
      end

      def client_options(options)
        # Keyfile options have higher priority over constructor defaults
        options['token_credential_uri'] ||= self.class::TOKEN_CREDENTIAL_URI
        options['audience'] ||= self.class::AUDIENCE
        options['scope'] ||= self.class::SCOPE

        # client options for initializing signet client
        { token_credential_uri: options['token_credential_uri'],
          audience: options['audience'],
          scope: Array(options['scope']),
          issuer: options['client_email'],
          signing_key: OpenSSL::PKey::RSA.new(options['private_key']) }
      end
    end
  end
end
