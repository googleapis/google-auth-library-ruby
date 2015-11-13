# Copyright 2010 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require 'webrick'
require 'launchy'

module Google
  module Auth
    # Varation on {Google::Auth::UserAuthorizer} adapted command line
    # scripts.
    #
    # Example usage using browser/embedded server:
    #
    #     credentials = authorizer.get_credentials('user@gmail.com') do |auth|
    #       auth.authorize_with_local_server
    #     end
    #
    # Requests that require authorization will start an embedded
    # web server on localhost and launch the user's browser. If unable to
    # launch a browser locally, out-of-band authorization can be performed:
    #
    # Example of out of band authorization:
    #
    #     credentials = authorizer.get_credentials('user@gmail.com') do |auth|
    #       url = auth.oob_auth_url
    #       puts "Open #{url} and enter the authorization code here "\
    #            "after authorizing the application."
    #       gets
    #     end
    #
    # @see {Google::Auth::AuthCallbackApp}
    class InstalledAppUserAuthorizer < Google::Auth::UserAuthorizer
      # Initialize the authorizer
      #
      # @param [Google::Auth::ClientID] client_id
      #  Configured ID & secret for this application
      # @param [String, Array<String>] scope
      #  Authorization scope to request
      # @param [Google::Auth::Stores::TokenStore] token_store
      #  Backing storage for persisting user credentials
      def initialize(client_id, scope, token_store = nil)
        super(client_id, scope, token_store, nil)
      end

      # Get credentials for the the user. A block may be provided
      # to handle the case when credentials are not present.
      #
      # @param [String] user_id
      #  Unique ID of the user for loading/storing credentials. Preference
      #  is to use the email address of the google account.
      # @yield [String] Authorization URL
      # @param [Array<String>, String] scope
      #  If specified, only returns credentials that have all
      #  the requested scopes
      # @return [Google::Auth::UserRefreshCredentials]
      #  User credentials
      # @yield [auth] Block to acquire the authorization code.
      # @yieldparam [AuthContext] auth
      # @yieldreturn [String] authorization code
      # @see {#request_authorization}
      def get_credentials(user_id, scope = nil, &block)
        credentials = super(user_id)
        if credentials.nil? && block_given?
          credentials = request_authorization(user_id, scope, &block)
        end
        credentials
      end

      # Request authorization. Does not check for existing credentials.
      #
      # Example usage using browser/embedded server:
      #
      #     creds = authorizer.request_authorization('user@gmail.com') do |auth|
      #       auth.authorize_with_local_server
      #     end
      #
      # Requests that require authorization will start an embedded
      # web server on localhost and launch the user's browser. If unable to
      # launch a browser locally, out-of-band authorization can be performed:
      #
      # Example of out of band authorization:
      #
      #     creds = authorizer.request_authorization('user@gmail.com') do |auth|
      #       url = auth.oob_auth_url
      #       puts "Open #{url} and enter the authorization code here "\
      #            "after authorizing the application."
      #       gets
      #     end
      #
      # @param [String] user_id
      #  Unique ID of the user for loading/storing credentials.
      # @yield [auth] Block to acquire the authorization code.
      # @param [Array<String>, String] scope
      #  Authorization scope to request. Overrides the instance scopes if not
      #  nil.
      # @yieldparam [AuthContext] auth
      # @yieldreturn [String] authorization code
      # @return [Google::Auth::UserRefreshCredentials]
      #  User credentials
      def request_authorization(user_id, scope = nil, &block)
        fail 'Block required' if block.nil?
        context = AuthContext.new(self, user_id, scope)
        code = block.call(context)
        return context.exchange_code(code) if code
        nil
      end

      # Helper passed to callbacks for performing the actual authorization.
      # Provides a choice between OOB mode or using a local webserver
      # for callbacks
      class AuthContext
        OOB_URI = 'urn:ietf:wg:oauth:2.0:oob'

        def initialize(authorizer, user_id, scope)
          @authorizer = authorizer
          @user_id = user_id
          @scope = scope
          @base_url = OOB_URI
        end

        # Returns the authorization URL for out-of-band flows. It is the
        # caller's responsibility to prompt the user to open the URL
        # and enter the resulting code of the authorization process.
        #
        # @return [String] Url to acquire authorization
        def oob_auth_url
          @authorizer.get_authorization_url(login_hint: @user_id,
                                            scope: @scope,
                                            base_url: @base_url)
        end

        # Requests authorization, using an emebedded server on localhost
        # to handle the callback.
        #
        # @param [Fixnum] local_port
        #  Port to run local webserver on
        # @return [String] authorization code
        def authorize_with_local_server(local_port = nil)
          local_port ||= 8081
          @base_url = "http://localhost:#{local_port}"
          auth_url = @authorizer.get_authorization_url(
            login_hint: @user_id,
            scope: @scope,
            base_url: @base_url)
          run_callback_server(local_port, auth_url)
        end

        # @param [String] code
        #  Authorization code to exchange
        # @return [Google::Auth::UserRefreshCredentials]
        #  User credentials
        # @see Google::Auth::UserAuthorizer#get_and_store_credentials_from_code
        def exchange_code(code)
          @authorizer.get_and_store_credentials_from_code(user_id: @user_id,
                                                          code: code,
                                                          base_url: @base_url)
        end

        private

        RESPONSE_BODY = <<-HTML
          <html>
            <head>
              <script>
                function closeWindow() {
                  window.open('', '_self', '');
                  window.close();
                }
                setTimeout(closeWindow, 10);
              </script>
            </head>
            <body>You may close this window.</body>
          </html>
        HTML

        # Start an HTTP server to handle the authorization callback.
        #
        # @param [Fixnum] local_port
        #  Port to run local webserver on
        # @param [String] url
        #  Authorization URL to launch browser for
        def run_callback_server(local_port, url)
          server = create_server(local_port)
          code = nil
          begin
            trap('INT') { server.shutdown }
            proc = lambda do |req, res|
              code = req.query['code']
              res.status = WEBrick::HTTPStatus::RC_ACCEPTED
              res.body = RESPONSE_BODY
              server.stop
            end
            server.mount_proc '/', &proc
            Launchy.open(url)
            server.start
          ensure
            server.shutdown
          end
          code
        end

        def create_server(local_port)
          WEBrick::HTTPServer.new(
            Port: local_port,
            BindAddress: 'localhost',
            Logger: WEBrick::Log.new(STDOUT, 0),
            AccessLog: []
          )
        end
      end
    end
  end
end
