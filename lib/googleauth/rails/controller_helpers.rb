require 'rails'
require 'googleauth/token_store'
require 'googleauth/web_user_authorizer'

module Google
  module Auth
    module Rails
      # Helpers for rails controllers to simplify the most common usage
      # patterns.
      #
      # In the most basic form, authorization can be added by declaring a
      # before_action filter for a controller:
      #
      #     before_action :require_google_credentials
      #
      # This assumes that:
      # - The authorization scope required is configured via
      #   `config.googleauth.scope`
      # - The unique ID of the user is available at `session[:user_id]`
      #
      # Upon passing the filter, the user credentials are available in the
      # instance variable `@google_user_credentials` and can be used to access
      # the corresponding APIs.
      #
      # The filter can be customized by supplying a block instead. This can be
      # used to supply a different user ID or require a different scope
      # depending on the controller. The following sample uses the Google API
      # client  from Google Drive:
      #
      #     class FileController < ApplicationController
      #       before_action do
      #         require_google_credentials(
      #           user_id: current_user.email,
      #           scope: 'https://www.googleapis.com/auth/drive')
      #       end
      #
      #       def index
      #         drive = Google::Apis::DriveV2::DriveService.new
      #         drive.authorization = @google_user_credentials
      #         @files = drive.list_files(q: "mimeType = 'application/pdf')
      #       end
      #     end
      #
      module ControllerHelpers
        # Ensure that user credentials are available for the request.
        # Intended to be used as a filter on controllers, but can be called
        # directly within a controller method as well.
        #
        # After calling, credentials are available via the
        # `@google_user_credentials` instance variable on the controller.
        #
        # If no credentials available, the user will be redirected for
        # authorization.
        #
        # @param [String] user_id
        #  Unique user ID to load credentials for. Defaults to
        #  `session[:user_id]` if nil.
        # @param [String] login_hint
        #  Optional email address or google profile ID of the user to request
        #  authorization for.
        # @param [Array<String>,String] scope
        #  Scope to require authorization for. If specified, credentials will
        #  only be made available if and only if they are authorized for the
        #  specified scope. If nil, uses the default scope configured for
        #  the app.
        # @return [Google::Auth::UserRefreshCredentials]
        #  Credentials, if present
        def require_google_credentials(options = {})
          @google_user_credentials = google_user_credentials(options)
          redirect_to_google_auth_url(options) if @google_user_credentials.nil?
          @google_user_credentials
        end

        # Retrieve user credentials.
        #
        # @param [String] user_id
        #  Unique user ID to load credentials for. Defaults to
        #  `session[:user_id]` if nil.
        # @param [String] scope
        #  Scope to require authorization for. If specified, credentials will
        #  only be made available if and only if they are authorized for the
        #  specified scope. If nil, no scope check is performed and any
        #  available credentials are returned as is.
        # @return [Google::Auth::UserRefreshCredentials]
        #  Credentials, if present
        def google_user_credentials(options = {})
          user_id = options[:user_id] || session[:user_id]
          google_user_authorizer.get_credentials(user_id,
                                                 request,
                                                 options[:scope])
        end

        # Redirects the user to request authorization.
        #
        # @param [String] login_hint
        #  Optional email address or google profile ID of the user to request
        #  authorization for.
        # @param [String] redirect_to
        #  Optional URL to proceed to after authorization complete. Defaults
        #  to the current URL.
        # @param [String, Array<String>] scope
        #  Authorization scope to request. Overrides the instance scopes
        #  if not nil.
        # @return [Google::Auth::UserRefreshCredentials]
        #  Credentials, if present
        def redirect_to_google_auth_url(options = {})
          url = google_user_authorizer.get_authorization_url(
            login_hint: options[:login_hint],
            request: request,
            redirect_to: options[:redirect_to],
            scope: options[:scope])
          redirect_to url
        end

        # Retrieves the default authorizer
        #
        # @return [Google::Auth::WebUserAuthorizer]
        def google_user_authorizer
          Google::Auth::WebUserAuthorizer.default
        end
      end
    end
  end
end
