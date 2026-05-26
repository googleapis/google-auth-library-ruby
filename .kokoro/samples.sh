#!/bin/bash

set -eo pipefail

# Install gems in the user directory because the default install directory
# is in a read-only location.
export GEM_HOME=$HOME/.gem
export PATH=$GEM_HOME/bin:$PATH

bundle install
BUNDLE_GEMFILE=samples/Gemfile bundle install

bundle exec rake samples load_kokoro_context=true
