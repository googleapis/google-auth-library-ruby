source "https://private-gems.liveramp.net"

# Specify your gem's dependencies in googleauth.gemspec
gemspec

group :development do
  source "https://public-gems.liveramp.net" do
    gem "bundler", ">= 1.9"
    gem "coveralls", "~> 0.7"
    gem "fakefs", "~> 0.6"
    gem "fakeredis", "~> 0.5"
    gem "google-style", "~> 0.3"
    gem "logging", "~> 2.0"
    gem "rack-test", "~> 0.6"
    gem "rake", "~> 10.0"
    gem "redis", "~> 3.2"
    gem "rspec", "~> 3.0"
    gem "simplecov", "~> 0.9"
    gem "sinatra"
    gem "webmock", "~> 1.21"
  end
end

platforms :jruby do
  group :development do
  end
end
