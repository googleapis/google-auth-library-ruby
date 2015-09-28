# Google Auth Library for Ruby

<dl>
  <dt>Homepage</dt><dd><a href="http://www.github.com/google/google-auth-library-ruby">http://www.github.com/google/google-auth-library-ruby</a></dd>
  <dt>Authors</dt><dd><a href="mailto:temiola@google.com">Tim Emiola</a></dd>
  <dt>Copyright</dt><dd>Copyright © 2015 Google, Inc.</dd>
  <dt>License</dt><dd>Apache 2.0</dd>
</dl>

[![Gem Version](https://badge.fury.io/rb/googleauth.svg)](http://badge.fury.io/rb/googleauth)
[![Build Status](https://secure.travis-ci.org/google/google-auth-library-ruby.png)](http://travis-ci.org/google/google-auth-library-ruby)
[![Coverage Status](https://coveralls.io/repos/google/google-auth-library-ruby/badge.png)](https://coveralls.io/r/google/google-auth-library-ruby)
[![Dependency Status](https://gemnasium.com/google/google-auth-library-ruby.png)](https://gemnasium.com/google/google-auth-library-ruby)

## Description

This is Google's officially supported ruby client library for using OAuth 2.0
authorization and authentication with Google APIs.

## Alpha

This library is in Alpha. We will make an effort to support the library, but
we reserve the right to make incompatible changes when necessary.

## Install

Be sure `https://rubygems.org/` is in your gem sources.

For normal client usage, this is sufficient:

```bash
$ gem install googleauth
```

## Application Default Credentials

This library provides an implementation of
[application default credentials][application default credentials] for Ruby.

The Application Default Credentials provide a simple way to get authorization
credentials for use in calling Google APIs.

They are best suited for cases when the call needs to have the same identity
and authorization level for the application independent of the user. This is
the recommended approach to authorize calls to Cloud APIs, particularly when
you're building an application that uses Google Compute Engine.

### Example Usage

```ruby
require 'googleauth'

# Get the environment configured authorization
scopes =  ['https://www.googleapis.com/auth/cloud-platform', 'https://www.googleapis.com/auth/compute']
authorization = Google::Auth.get_application_default(scopes)

# Add the the access token obtained using the authorization to a hash, e.g
# headers.
some_headers = {}
authorization.apply(some_headers)

```

## User Authorization

Applications that need to act on behalf of users can obtain credentials
using `Google::Auth::UserAuthorizer`, `Google::Auth::WebUserAuthorizer`,
or `Google::Auth::InstalledAppUserAuthorizer` depending on the use case.
While `UserAuthorizer` can be used in all contexts, both `WebUserAuthorizer`
and `InstalledAppUserAuthorizer` present simpler interfaces for web and
command line applications, respectively.

### Example usage (command line)

```ruby
require 'googleauth'

# Load the client ID and secrets along with stored credentials
client_id = Google::Auth::ClientId.from_file('client_secret.json')
storage = Google::Auth::Stores::FileTokenStore.new(:file => 'user_credentials.yaml')
scope = 'https://www.googleapis.com/auth/drive'
authorizer = Google::Auth::InstalledAppUserAuthorizer.new(client_id, scope, storage)

# Retrieve credentials for an account. Launches a browser to authorize if needed.
credentials = authorizer.get_credentials('user@example.com')
```

### Example usage (Rails)

Add to Gemfile:

    gem 'googleauth', :require => 'googleauth'

Then run the following commands:

```bash
$ bundle install
$ rails g googleauth
$ bin/rake db:migrate
```

This will configure your Rails app to store user credentials in your database
as well as sets up a route for the callback at `/oauth2callback`. It also
creates an initializer at `config/intializers/googleauth.rb` which can
customized if needed.

You'll also need to configure and download your application client ID
and secret from the [Google Developers Console](https://console.developers.google.com)
and save it to `config/client_secret.json`

To require user authorization for a controller, call `require_google_credentials`.
For simple cases where the user is already authenticated and the user ID
is available in `session[:user_id]`, this can be called as a filter:

```ruby
class GreetingController < ApplicationController
  # ensure @google_user_credentials exists in any actions
  before_action :require_google_credentials

  ...
end
```

See [ControllerHelpers](/lib/googleauth/rails/controller_helpers.rb) and
[WebUserAuthorizer](/lib/googleauth/web_user_authorizer.rb) for additional
usage information.

## License

This library is licensed under Apache 2.0. Full license text is
available in [COPYING][copying].

## Contributing

See [CONTRIBUTING][contributing].

## Support

Please
[report bugs at the project on Github](https://github.com/google/google-auth-library-ruby/issues). Don't
hesitate to
[ask questions](http://stackoverflow.com/questions/tagged/google-auth-library-ruby)
about the client or APIs on [StackOverflow](http://stackoverflow.com).

[google-apis-ruby-client]: (https://github.com/google/google-api-ruby-client)
[application default credentials]: (https://developers.google.com/accounts/docs/application-default-credentials)
[contributing]: https://github.com/google/google-auth-library-ruby/tree/master/CONTRIBUTING.md
[copying]: https://github.com/google/google-auth-library-ruby/tree/master/COPYING
