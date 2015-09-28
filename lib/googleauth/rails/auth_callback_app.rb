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

require 'rack/request'
require 'googleauth/web_user_authorizer'

module Google
  module Auth
    # Small Rack app which acts as the default callback handler for the app.
    #
    # To configure in Rails, add to routes.rb:
    #
    #     match '/oauth2callback', to: Google::Auth::Web::AuthCallbackApp, via: :all
    #
    # With Rackup, add to config.ru:
    #
    #     map '/oauth2callback' { run Google::Auth::Web::AuthCallbackApp }
    #
    # Or in a classic Sinatra app:
    #
    #     get('/oauth2callback') { Google::Auth::Web::AuthCallbackApp.call(env) }
    #
    # @see {Google::Auth::Web::WebUserAuthorizer}
    class AuthCallbackApp
      LOCATION_HEADER = 'Location'
      REDIR_STATUS = 302
      ERROR_STATUS = 500

      # Handle a rack request. Simply stores the results the authorization
      # in the session temporarily and redirects back to to the previously
      # saved redirect URL. Credentials can be later retrieved by calling.
      # {Google::Auth::Web::WebUserAuthorizer#get_credentials}
      #
      # See {Google::Auth::Web::WebUserAuthorizer#get_authorization_uri}
      # for how to initiate authorization requests.
      #
      # @param [Hash] env
      #  Rack environment
      # @return [Array]
      #  HTTP response
      def self.call(env)
        request = Rack::Request.new(env)
        return_url = WebUserAuthorizer.handle_auth_callback_deferred(request)
        if return_url
          [REDIR_STATUS, { LOCATION_HEADER => return_url }, []]
        else
          [ERROR_STATUS, {}, ['No return URL is present in the request.']]
        end
      end

      def call(env)
        self.class.call(env)
      end
    end
  end
end
