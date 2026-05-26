# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

require "rake/testtask"
require "rspec/core/rake_task"
require "rubocop/rake_task"
require "yard"
require "multi_json"

# Helper to print files
def print_files pattern
  files = Dir.glob pattern
  puts "Matched #{files.size} files."
  files.each { |f| puts "  #{f}" } if Rake.application.options.trace
end

Rake::TestTask.new :minitest_run do |t|
  t.libs << "test"
  t.pattern = "test/**/*_test.rb"
  t.warning = true
end

desc "Run Minitest tests"
task :test do
  puts "--- Starting Minitest tests ---"
  print_files "test/**/*_test.rb"
  Rake::Task[:minitest_run].invoke
  puts "--- Finished Minitest tests ---"
end

RSpec::Core::RakeTask.new :rspec_run do |t|
  t.rspec_opts = "-Ilib -Ispec"
end

desc "Run RSpec specs"
task :spec do
  puts "--- Starting RSpec specs ---"
  print_files "spec/**/*_spec.rb"
  Rake::Task[:rspec_run].invoke
  puts "--- Finished RSpec specs ---"
end

RuboCop::RakeTask.new :rubocop_run

desc "Run RuboCop checks"
task :rubocop do
  puts "--- Starting RuboCop checks ---"
  Rake::Task[:rubocop_run].invoke
  puts "--- Finished RuboCop checks ---"
end

Rake::TestTask.new :integration_run do |t|
  t.libs << "integration"
  t.pattern = "integration/**/*_test.rb"
  t.warning = true
end

desc "Run integration tests"
task :integration do
  puts "--- Starting integration tests ---"
  print_files "integration/**/*_test.rb"
  Rake::Task[:integration_run].invoke
  puts "--- Finished integration tests ---"
end

desc "Build the gem"
task :build do
  puts "--- Starting gem build ---"
  sh "gem build googleauth.gemspec"
  puts "--- Finished gem build ---"
end

YARD::Config.options[:generate_output_flag] = true
YARD::Rake::YardocTask.new :yardoc_run

desc "Generate documentation"
task :yardoc do
  puts "--- Starting documentation generation ---"
  Rake::Task[:yardoc_run].invoke
  puts "--- Finished documentation generation ---"
end

desc "Run Link checks"
task linkinator: :yardoc do
  puts "--- Starting link checks ---"
  sh "npx -y linkinator ./doc --skip stackoverflow.com"
  puts "--- Finished link checks ---"
end

# @private
# Guard variable to ensure Kokoro environment is only loaded once.
@loaded_kokoro_env = false

##
# Loads environment variables and service account credentials from the Kokoro
# environment.
#
# This method replicates the mechanics used in `google-cloud-ruby` via Toys
# to prepare the environment for integration and samples tests in CI.
#
# It expects the following resources to be present in the directory pointed to
# by the `KOKORO_GFILE_DIR` environment variable:
#
# 1. `ruby_env_vars.json`: A JSON file containing a flat hash of key-value
#    pairs representing environment variables. This file is REQUIRED if
#    `KOKORO_GFILE_DIR` is set, as it is the primary mechanism for passing
#    environment config in Kokoro.
# 2. `secret_manager/ruby-main-ci-service-account`: A file containing the
#    JSON key for the service account used for testing. This file is optional,
#    but required for tests that need live cloud access.
#
# @raise [RuntimeError] if `KOKORO_GFILE_DIR` is set but `ruby_env_vars.json`
#        is missing.
#
# @example Usage in Rake task:
#   # To trigger this via command line:
#   # bundle exec rake samples load_kokoro_context=true
#   if ENV["load_kokoro_context"] == "true"
#     load_kokoro_env
#   end
#
def load_kokoro_env
  return if @loaded_kokoro_env
  @loaded_kokoro_env = true

  gfile_dir = ENV["KOKORO_GFILE_DIR"]
  return unless gfile_dir

  load_ruby_env_vars gfile_dir
  load_sa_credentials gfile_dir
end

# @private
def load_ruby_env_vars gfile_dir
  env_vars_file = File.join gfile_dir, "ruby_env_vars.json"
  unless File.file? env_vars_file
    raise "Kokoro environment file missing: #{env_vars_file}. " \
          "Expected to be populated by populate-secrets.sh."
  end

  puts "Loading environment variables from #{env_vars_file}"
  require "json"
  env_vars = JSON.parse File.read env_vars_file
  env_vars.each { |k, v| ENV[k] ||= v }
end

# @private
def load_sa_credentials gfile_dir
  keyfile = File.join gfile_dir, "secret_manager", "ruby-main-ci-service-account"
  if File.file? keyfile
    ENV["GOOGLE_APPLICATION_CREDENTIALS"] = keyfile

    # Extract project_id from the key file if available
    require "json"
    key_data = JSON.parse File.read keyfile
    if key_data["project_id"]
      ENV["GOOGLE_CLOUD_PROJECT"] ||= key_data["project_id"]
    end

    ENV["GCLOUD_TEST_KEYFILE_JSON"] = File.read keyfile
  else
    puts "Warning: Secret file not found at #{keyfile}."
    puts "Falling back to ambient credentials (e.g., default Compute Engine service account)."
  end
end

desc "Run samples tests. Usage: bundle exec rake samples load_kokoro_context=true"
task :samples do
  puts "--- Starting samples tests ---"

  # Load Kokoro environment if requested via command line override
  if ENV["load_kokoro_context"] == "true"
    load_kokoro_env
  end

  cmd = "BUNDLE_GEMFILE=samples/Gemfile bundle exec ruby -Ilib -Isamples -e " \
        "'Dir.glob(\"samples/acceptance/*_test.rb\").each{|f| require File.expand_path(f)}'"
  sh cmd
  puts "--- Finished samples tests ---"
end

desc "Run all CI tasks"
task ci: [:test, :spec, :rubocop, :integration, :build, :yardoc, :linkinator]

# Default task
task default: [:test, :spec, :rubocop]
