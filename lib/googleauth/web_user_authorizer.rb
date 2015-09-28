# Copyright 2014, Google Inc.
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

require 'multi_json'
require 'googleauth/signet'
require 'googleauth/user_authorizer'
require 'googleauth/user_refresh'
require 'securerandom'

module Google
  module Auth
    # Varation on {Google::Auth::UserAuthorizer} adapted for Rack based
    # web applications.
    #
    # Example usage:
    #
    #     get('/') do
    #       user_id = request.session['user_email']
    #       credentials = authorizer.get_credentials(user_id, request)
    #       if credentials.nil?
    #         redirect authorizer.get_redirect_uri(user_id, request)
    #       end
    #       # Credentials are valid, can call APIs
    #       ...
    #    end
    #
    #    get('/oauth2callback') do
    #       user_id = request.session['user_email']
    #      _, return_uri = authorizer.handle_auth_callback(user_id, request)
    #      redirect return_uri
    #    end
    #
    # Instead of implementing the callback directly, applications are encouraged to
    # use {Google::Auth::Web::AuthCallbackApp} instead.
    #
    # @see {Google::Auth::Web::AuthCallbackApp}
    # @note Requires sessions are enabled
    class WebUserAuthorizer < Google::Auth::UserAuthorizer
      STATE_PARAM = 'state'
      AUTH_CODE_KEY = 'code'
      ERROR_CODE_KEY = 'error'
      SESSION_ID_KEY = 'session_id'
      CALLBACK_STATE_KEY = 'g-auth-callback'
      CURRENT_URI_KEY = 'current_uri'
      XSRF_KEY = 'g-xsrf-token'
      SCOPE_KEY = 'scope'

      class << self
        attr_accessor :default
      end

      # Handle the result of the oauth callback. This version defers the exchange
      # of the code by temporarily stashing the results in the user's session. This
      # allows apps to use the generic {Google::Auth::Web::AuthCallbackApp} handler
      # for the callback without any additional customization.
      #
      # Apps that wish to handle the callback directly should use {#handle_auth_callback}
      # instead.
      #
      # @param [Rack::Request] request
      #  Current request
      def self.handle_auth_callback_deferred(request)
        callback_state, redirect_uri = self.extract_callback_state(request)
        request.session[CALLBACK_STATE_KEY] = MultiJson.dump(callback_state)
        return redirect_uri
      end

      # Initialize the authorizer
      #
      # @param [Google::Auth::ClientID] client_id
      #  Configured ID & secret for this application
      # @param [String, Array<String>] scope
      #  Authorization scope to request
      # @param [Google::Auth::Stores::TokenStore] token_store
      #  Backing storage for persisting user credentials
      # @param [String] callback_uri
      #  URL (either absolute or relative) of the auth callback. Defaults to '/oauth2callback'
      def initialize(client_id, scope, token_store, callback_uri = nil)
        super(client_id, scope, token_store, callback_uri)
      end


      # Handle the result of the oauth callback. Exchanges the authorization code from the
      # request and persists to storage.
      #
      # @param [String] user_id
      #  Unique ID of the user for loading/storing credentials.
      # @param [Rack::Request] request
      #  Current request
      # @return (Google::Auth::UserRefreshCredentials, String)
      #  credentials & next URL to redirect to
      def handle_auth_callback(user_id, request)
        callback_state, redirect_uri = WebUserAuthorizer.extract_callback_state(request)
        WebUserAuthorizer.validate_callback_state(callback_state, request)
        credentials = get_and_store_credentials_from_code(:user_id => user_id,
                                                          :code => callback_state[AUTH_CODE_KEY],
                                                          :scope => callback_state[SCOPE_KEY],
                                                          :base_url => request.url)
        return credentials, redirect_uri
      end

      # Build the URL for requesting authorization.
      #
      # @param [String] login_hint
      #  Login hint if need to authorize a specific account. Should be a user's email address
      #  or unique profile ID.
      # @param [Rack::Request] request
      #  Current request
      # @param [String] redirect_to
      #  Optional URL to proceed to after authorization complete. Defaults to the current URL.
      # @param [String, Array<String>] scope
      #  Authorization scope to request. Overrides the instance scopes if not nil.
      # @return [String]
      #  Authorization url
      def get_authorization_url(options = {})
        options = options.dup
        request = options[:request]
        fail "Request is required." if request.nil?
        fail "Sessions must be enabled" if request.session.nil?

        redirect_to = options[:redirect_to] || request.url
        request.session[XSRF_KEY] = SecureRandom.base64
        options[:state] = MultiJson.dump({
          SESSION_ID_KEY => request.session[XSRF_KEY],
          CURRENT_URI_KEY => redirect_to
        })
        options[:base_url] = request.url
        super(options)
      end


      # Fetch stored credentials for the user.
      #
      # @param [String] user_id
      #  Unique ID of the user for loading/storing credentials.
      # @param [Rack::Request] request
      #  Current request
      # @param [Array<String>, String] scope
      #  If specified, only returns credentials that have all the requested scopes
      # @return [Google::Auth::UserRefreshCredentials]
      #  Stored credentials, nil if none present
      # @raise [Signet::AuthorizationError]
      #  May raise an error if an authorization code is present in the session
      #  and exchange of the code fails
      def get_credentials(user_id, request, scope = nil)
        if request.session.has_key?(CALLBACK_STATE_KEY)
          # Note - in theory, no need to check required scope as this is expected
          # to be called immediately after a return from authorization
          state_json = request.session.delete(CALLBACK_STATE_KEY)
          callback_state = MultiJson.load(state_json)
          WebUserAuthorizer.validate_callback_state(callback_state, request)
          get_and_store_credentials_from_code(:user_id => user_id,
                                              :code => callback_state[AUTH_CODE_KEY],
                                              :scope => callback_state[SCOPE_KEY],
                                              :base_url => request.url)
        else
          super(user_id, scope)
        end
      end

      private

      def self.extract_callback_state(request)
        state = MultiJson.load(request[STATE_PARAM] || '{}')
        redirect_uri = state[CURRENT_URI_KEY]
        callback_state = {
          AUTH_CODE_KEY => request[AUTH_CODE_KEY],
          ERROR_CODE_KEY =>  request[ERROR_CODE_KEY],
          SESSION_ID_KEY => state[SESSION_ID_KEY],
          SCOPE_KEY => request[SCOPE_KEY]
        }
        return callback_state, redirect_uri
      end

      # Verifies the results of an authorization callback
      #
      # @param [Hash] state
      #  Callback state
      # @option state [String] AUTH_CODE_KEY
      #  The authorization code
      # @option state [String] ERROR_CODE_KEY
      #  Error message if failed
      # @param [Rack::Request] request
      #  Current request
      def self.validate_callback_state(state, request)
        fail Signet::AuthorizationError, "Missing authorization code in request" if state[AUTH_CODE_KEY].nil?
        fail Signet::AuthorizationError, "Authorization error: #{state[ERROR_CODE_KEY]}" if state[ERROR_CODE_KEY]
        fail Signet::AuthorizationError, "State token does not match expected value" if request.session[XSRF_KEY] != state[SESSION_ID_KEY]
      end
    end
  end
end
