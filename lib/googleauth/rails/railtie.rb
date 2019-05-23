require 'rails'
require 'googleauth/token_store'
require 'googleauth/web_user_authorizer'
require 'googleauth/rails/controller_helpers'

module Google
  module Auth
    # Rails-specific extensions
    module Rails
      # Railtie for simplified integration with Rails. Exposes configuration
      # via Rails config and performs initialiation on startup.
      class Railtie < Rails::Railtie
        MISSING_CLIENT_ID_ERROR =
          'Unable to configure googleauth library, no client secret available'
        MISSING_TOKEN_STORE_ERROR =
          'Unable to configure googleauth library, no token store configured'
        config.googleauth = ActiveSupport::OrderedOptions.new
        config.googleauth.token_store = :active_record
        config.googleauth.client_secret_path = nil
        config.googleauth.id = nil
        config.googleauth.secret = nil
        config.googleauth.scope = %w(email profile)
        config.googleauth.callback_uri = '/oauth2callback'
        config.googleauth.token_store_options = {}
        config.googleauth.include_helpers = true

        # Initialize authorizers based on config
        config.after_initialize do
          opts = config.googleauth
          client_id = load_client_id
          token_store = load_token_store
          if client_id.nil?
            Rails.logger.warn(MISSING_CLIENT_ID_ERROR)
          elsif token_store.nil?
            Rails.logger.warn(MISING_TOKEN_STORE_ERROR)
          else
            Google::Auth::WebUserAuthorizer.default =
              Google::Auth::WebUserAuthorizer.new(
                client_id,
                opts.scope,
                token_store,
                opts.callback_uri)
            if config.googleauth.include_helpers
              ActionController::Base.send(
                :include, Google::Auth::Rails::ControllerHelpers)
            end
          end
        end

        # Load the client ID
        def load_client_id
          opts = config.googleauth
          return Google::Auth::ClientId.new(opts.id, opts.secret) if opts.id
          client_secret = config.googleauth.client_secret_path ||
                          File.join(Rails.root, 'config', 'client_secret.json')
          return nil unless File.exist?(client_secret)
          Rails.logger.info("Initializing client ID from #{client_secret}")
          Google::Auth::ClientId.from_file(client_secret)
        end

        # Initialize the token store
        def load_token_store
          token_store = config.googleauth.token_store
          case token_store
          when Google::Auth::TokenStore
            token_store
          when :active_record
            require 'googleauth/stores/active_record_token_store'
            Google::Auth::Stores::ActiveRecordTokenStore.new(
              config.googleauth.token_store_options)
          when :redis
            require 'googleauth/stores/redis_token_store'
            Google::Auth::Stores::RedisTokenStore.new(
              config.googleauth.token_store_options)
          when :file
            require 'googleauth/stores/file_token_store'
            Google::Auth::Stores::FileTokenStore.new(
              config.googleauth.token_store_options)
          else
            fail "Unsupported token store: #{token_store}"
          end
        end
      end
    end
  end
end
