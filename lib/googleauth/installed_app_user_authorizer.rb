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
    # scripts. Requests that require authorization will start an embedded
    # web server on localhost and launch the user's browser.
    #
    # Example usage using browser/embedded server:
    #
    #     credentials = authorizer.get_credentials('example@gmail.com')
    #
    # If unable to launch a browser locally, a block can be supplied to
    # handle the authorization out of band.
    #
    # Example of out of band authorization:
    #
    #     credentials = authorizer.get_credentials('example@gmail.com') do |url|
    #       puts "Open #{url} and enter the authorization code here "\
    #            "after authorizing the application."
    #       gets
    #     end
    #
    # @see {Google::Auth::AuthCallbackApp}
    # @note Requires sessions are enabled
    class InstalledAppUserAuthorizer < Google::Auth::UserAuthorizer
      OOB_URI = 'urn:ietf:wg:oauth:2.0:oob'
      attr_accessor :local_port

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
        @local_port = 8081
      end

      # Get credentials for the the user. May block to attempt authorization
      # if no stored credentials are found locally.
      #
      # @param [String] user_id
      #  Unique ID of the user for loading/storing credentials. Preference
      #  is to use the email address of the google account.
      # @yield [String] Authorization URL
      # @return [Google::Auth::UserRefreshCredentials]
      #  User credentials
      # @see {#request_authorization}
      def get_credentials(user_id, &block)
        credentials = super(user_id)
        credentials = request_authorization(user_id, &block) if credentials.nil?
        credentials
      end

      # The default behavior for acquiring authorization launches the
      # user's default browser along with running an embedded server
      # on localhost to handle the callback. For cases where launching
      # a browser is infeasible (e.g. terminal only) a block may be supplied
      # instead. The block will be called with the authorization URL and
      # is expected to return the authorization code after prompting the user.
      #
      # @param [String] user_id
      #  Unique ID of the user for loading/storing credentials.
      # @yield [String] Authorization URL
      # @return [Google::Auth::UserRefreshCredentials]
      #  User credentials
      def request_authorization(user_id, &block)
        if block
          base_url = OOB_URI
          handler = proc { |url| block.call(url) }
        else
          base_url = "http://localhost:#{@local_port}"
          handler = proc { |url| run_callback_server(url) }
        end
        auth_url = get_authorization_url(login_hint: user_id,
                                         base_url: base_url)
        code = handler.call(auth_url)
        get_and_store_credentials_from_code(user_id: user_id,
                                            code: code,
                                            base_url: base_url)
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
      # @param [String] url
      #  Authorization URL to launch browser for
      def run_callback_server(url)
        server = create_server(@local_port)
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

      def create_server(port)
        WEBrick::HTTPServer.new(
          Port: port,
          BindAddress: 'localhost',
          Logger: WEBrick::Log.new(STDOUT, 0),
          AccessLog: []
        )
      end
    end
  end
end
