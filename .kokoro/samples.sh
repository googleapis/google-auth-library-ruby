#!/bin/bash

set -eo pipefail

# Install gems in the user directory because the default install directory
# is in a read-only location.
export GEM_HOME=$HOME/.gem
export PATH=$GEM_HOME/bin:$PATH

gem install --no-document toys

# To run acceptance tests for samples, we need the `sample_loader.rb` helper
# from the `googleapis/ruby-common-tools` repository.
#
# Previously, this file was downloaded dynamically at runtime in `helper.rb`
# using `Toys::Utils::GitCache`. However, that approach creates a dependency
# on Toys internal utilities during test execution, which fails when running
# within an isolated bundle (e.g., via Bundler).
#
# To make the tests more robust and independent of the task runner's internal
# state, we explicitly download the helper file here before executing the tests.
# This does not change the testing infrastructure; it only makes the download
# step explicit and reliable.
curl -sSL https://raw.githubusercontent.com/googleapis/ruby-common-tools/main/lib/sample_loader.rb -o samples/acceptance/sample_loader.rb

toys samples < /dev/null
