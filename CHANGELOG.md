## 0.4.2 (05/08/2015)

### Changes

* Updated UserRefreshCredentials hash to use string keys ([@haabator][])
[#36](https://github.com/google/google-auth-library-ruby/issues/36)

* Add support for a system default credentials file. ([@mr-salty][])
[#33](https://github.com/google/google-auth-library-ruby/issues/33)

* Fix bug when loading credentials from ENV ([@dwilkie][])
[#31](https://github.com/google/google-auth-library-ruby/issues/31)

* Relax the constraint of dependent version of multi_json ([@igrep][])
[#30](https://github.com/google/google-auth-library-ruby/issues/30)

### Changes

* Enables passing credentials via environment variables. ([@haabaato][])
[#27](https://github.com/google/google-auth-library-ruby/issues/27)

## 0.4.1 (25/04/2015)

### Changes

* Improves handling of --no-scopes GCE authorization ([@tbetbetbe][])
* Refactoring and cleanup ([@joneslee85][])

## 0.4.0 (25/03/2015)

### Changes

* Adds an implementation of JWT header auth ([@tbetbetbe][])

## 0.3.0 (23/03/2015)

### Changes

* makes the scope parameter's optional in all APIs. ([@tbetbetbe][])
* changes the scope parameter's position in various constructors. ([@tbetbetbe][])

[@dwilkie]: https://github.com/dwilkie
[@haabaato]: https://github.com/haabaato
[@igrep]: https://github.com/igrep
[@joneslee85]: https://github.com/joneslee85
[@mr-salty]: https://github.com/mr-salty
[@tbetbetbe]: https://github.com/tbetbetbe
