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

desc "Run all CI tasks"
task ci: [:test, :spec, :rubocop, :integration, :build, :yardoc, :linkinator]

# Default task
task default: [:test, :spec, :rubocop]
