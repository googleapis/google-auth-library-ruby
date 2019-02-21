## 0.8.0 (2019/01/02)

* Support connection options :default_connection and :connection_builder when creating credentials that need to refresh OAuth tokens. This lets clients provide connection objects with custom settings, such as proxies, needed for the client environment.
* Removed an unnecessary warning about project IDs.

## 0.7.1 (2018/10/25)

* Make load_gcloud_project_id module function.

## 0.7.0 (2018/10/24)

* Add project_id instance variable to UserRefreshCredentials, ServiceAccountCredentials, and Credentials.

## 0.6.7 (2018/10/16)

* Update memoist dependency to ~> 0.16.

## 0.6.6 (2018/08/22)

* Remove ruby version warnings.

## 0.6.5 (2018/08/16)

* Fix incorrect http verb when revoking credentials.
* Warn on EOL ruby versions.

## 0.6.4 (2018/08/03)

* Resolve issue where DefaultCredentials constant was undefined.

## 0.6.3 (2018/08/02)

* Resolve issue where token_store was being written to twice

## 0.6.2 (2018/08/01)

* Add warning when using cloud sdk credentials

## 0.6.1 (2017/10/18)

* Fix file permissions

## 0.6.0 (2017/10/17)

### 0.7.2 / 2019-02-21

* switch gcloud command to IO.popen from backticks (#194)
* Remove warning while looking up project_id (#184)
* Support configuration of the connection object used to fetch tokens (#185)
* Add example for auth with ENV vars (#156)
* Fix bundler gem name and pin to 1.17.3
* use newest ruby versions for kokoro (#172)
* Update github issue templates (#173)
* remove travis and add 2.6 to list of rubies to test against (#191)
* Update version and changelog for 0.8.0 release (#188)
* Pin bundler to 1.17.3 for now when running travis
* Loosen bundler dependency to fix travis

### Changes

* Support ruby-jwt 2.0
* Add simple credentials class

## 0.5.3 (2017/07/21)

### Changes

* Fix file permissions on the gem's `.rb` files.

## 0.5.2 (2017/07/19)

### Changes

* Add retry mechanism when fetching access tokens in `GCECredentials` and `UserRefreshCredentials` classes.
* Update Google API OAuth2 token credential URI to v4.

## 0.5.1 (2016/01/06)

### Changes

* Change header name emitted by `Client#apply` from "Authorization" to "authorization" ([@murgatroid99][])
* Fix ADC not working on some windows machines ([@vsubramani][])
[#55](https://github.com/google/google-auth-library-ruby/issues/55)

## 0.5.0 (2015/10/12)

### Changes

* Initial support for user credentials ([@sqrrrl][])
* Update Signet to 0.7

## 0.4.2 (2015/08/05)

### Changes

* Updated UserRefreshCredentials hash to use string keys ([@haabaato][])
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

## 0.4.1 (2015/04/25)

### Changes

* Improves handling of --no-scopes GCE authorization ([@tbetbetbe][])
* Refactoring and cleanup ([@joneslee85][])

## 0.4.0 (2015/03/25)

### Changes

* Adds an implementation of JWT header auth ([@tbetbetbe][])

## 0.3.0 (2015/03/23)

### Changes

* makes the scope parameter's optional in all APIs. ([@tbetbetbe][])
* changes the scope parameter's position in various constructors. ([@tbetbetbe][])

[@dwilkie]: https://github.com/dwilkie
[@haabaato]: https://github.com/haabaato
[@igrep]: https://github.com/igrep
[@joneslee85]: https://github.com/joneslee85
[@mr-salty]: https://github.com/mr-salty
[@tbetbetbe]: https://github.com/tbetbetbe
[@murgatroid99]: https://github.com/murgatroid99
[@vsubramani]: https://github.com/vsubramani
