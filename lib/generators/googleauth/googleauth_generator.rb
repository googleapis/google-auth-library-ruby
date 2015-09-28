# Rails generator for configuring the google auth library for Rails. Performs the following actions
#
# - Creates a route for "/oauth2callback' in `config/routes.rb` for the 3LO callback handler
# - Generates a migration for storing user credentials via ActiveRecord
# - Creates an initializer for further customization
#
class GoogleauthGenerator < Rails::Generators::Base
  source_root File.expand_path('../templates', __FILE__)
  class_option :generate_route, :type => :boolean, :default => true, :description => "Whether or not to insert routes in config/routes.rb"
  class_option :generate_migration, :type => :boolean, :default => true, :description => "Whether or not to generate a migration for token storage"
  class_option :generate_initializer, :type => :boolean, :default => true, :description => "Wheter or not to generate an initializer"

  def generate_config
    route "match '/oauth2callback', to: Google::Auth::AuthCallbackApp, via: :all" unless options.skip_route
    generate "migration", "CreateGoogleAuthTokens user_id:string:index token:string" unless options.skip_migration
    copy_file "googleauth.rb", "config/initializers/googleauth.rb" unless options.skip_initializer
    if !client_secret_exists?
      say "Please download your application credentials from http://console.developers.google.com and copy to config/client_secret.json."
    end
  end

  def client_secret_exists?
    path = File.join(Rails.root, 'config', 'client_secret.json')
    File.exists?(path)
  end
end
