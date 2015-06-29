# -*- ruby -*-
# encoding: utf-8
$LOAD_PATH.push File.expand_path('../lib', __FILE__)
require 'googleauth/version'

Gem::Specification.new do |s|
  s.name          = 'googleauth'
  s.version       = Google::Auth::VERSION
  s.authors       = ['Tim Emiola']
  s.email         = 'temiola@google.com'
  s.homepage      = 'https://github.com/google/google-auth-library-ruby'
  s.summary       = 'Google Auth Library for Ruby'
  s.license       = 'Apache-2.0'
  s.description   = <<-eos
   Allows simple authorization for accessing Google APIs.
   Provide support for Application Default Credentials, as described at
   https://developers.google.com/accounts/docs/application-default-credentials
  eos

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- spec/*`.split("\n")
  s.executables   = `git ls-files -- bin/*.rb`.split("\n").map do |f|
    File.basename(f)
  end
  s.require_paths = ['lib']
  s.platform      = Gem::Platform::RUBY

  s.add_dependency 'faraday', '~> 0.9'
  s.add_dependency 'logging', '~> 2.0'
  s.add_dependency 'jwt', '~> 1.4'
  s.add_dependency 'memoist', '~> 0.12'
  s.add_dependency 'multi_json', '~> 1.11'
  s.add_dependency 'signet', '~> 0.6'

  s.add_development_dependency 'bundler', '~> 1.9'
  s.add_development_dependency 'simplecov', '~> 0.9'
  s.add_development_dependency 'coveralls', '~> 0.7'
  s.add_development_dependency 'fakefs', '~> 0.6'
  s.add_development_dependency 'rake', '~> 10.0'
  s.add_development_dependency 'rubocop', '~> 0.30'
  s.add_development_dependency 'rspec', '~> 3.0'
end
