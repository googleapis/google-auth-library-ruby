# Default token store uses ActiveRecord. Use the following to use Redis instead
#
# Rails.application.config.googleauth.token_store = :redis
# Rails.application.config.googleauth.token_store_options = {
#  :url => 'redis://localhost:6380'
# }

# Default client secret location is config/client_secret.json. Alternate
# locations can be specified as:
# Rails.application.config.googleauth.client_secret_path = '/etc/googleauth/client_secret.json'
#
# Or configured directly:
#  Rails.application.config.googleauth.id = 'myclientsecret'
# Rails.application.config.googleauth.secret = 'mysecret'

# Default scopes to request
# Rails.application.config.googleauth.scope = %w(email profile)

# Redirect URI path
# Rails.application.config.googleauth.callback_uri = '/oauth2callback'

# Uncommment to disable automatic injection of helpers into controllers.
# If disabled, helpers can me added as needed by
# including the module 'Google::Auth::ControllerHelpers'
# Rails.application.config.googleauth.include_helpers = false
