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

## Example Usage

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

## Application Default Credentials

This library provides an implementation of
[application default credentials][application default credentials] for Ruby.

The Application Default Credentials provide a simple way to get authorization
credentials for use in calling Google APIs.

They are best suited for cases when the call needs to have the same identity
and authorization level for the application independent of the user. This is
the recommended approach to authorize calls to Cloud APIs, particularly when
you're building an application that uses Google Compute Engine.

## What about auth in google-apis-ruby-client?

The goal is for all auth done by
[google-apis-ruby-client][google-apis-ruby-client] to be performed by this
library. I.e, eventually google-apis-ruby-client will just take a dependency
on this library.  This update is a work in progress, but should be completed
by Q2 2015.

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
