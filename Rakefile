# frozen_string_literal: true

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

require "bundler/gem_tasks"
require "json"
require "open3"
require "rake/clean"
require "rake/testtask"
require "rspec/core/rake_task"
require "rubocop/rake_task"
require "yard"

# The entries in .gitignore. rake/clean already removes "**/*~".
CLEAN.include "**/*.gem", "**/*.rbc", ".config", "coverage", "InstalledFiles", "pkg", "spec/reports", "test/tmp",
              "test/version_tmp", "tmp", "**/.dat*", "**/.repl_history", "build", ".yardoc", "_yardoc", "doc",
              "rdoc", ".bundle", "lib/bundler/man", "**/.rvmrc", "node_modules", "package-lock.json"

RSpec::Core::RakeTask.new :spec

Rake::TestTask.new :test do |t|
  t.libs = ["lib", "test"]
  t.test_files = FileList["test/**/*_test.rb"]
  t.warning = false
end

Rake::TestTask.new :integration do |t|
  t.libs = ["lib", "integration"]
  t.test_files = FileList["integration/**/*_test.rb"]
  t.warning = false
end

RuboCop::RakeTask.new

YARD::Rake::YardocTask.new :yardoc

desc "Alias for yardoc, used by the release tooling"
task yard: :yardoc

desc "Check the links in the generated documentation"
task linkinator: :yardoc do
  output, status = Open3.capture2 "npx", "linkinator", "./doc", "--skip", "stackoverflow.com"
  puts output
  broken = output.lines.select { |line| line =~ /^\[(\d+)\]/ && Regexp.last_match(1) != "200" }
  broken.each { |line| puts line }
  abort "linkinator failed" unless status.success? && broken.empty?
end

namespace :linkinator do
  desc "Install linkinator"
  task :install do
    sh "npm", "install", "linkinator"
  end
end

# On Kokoro, load the shared environment variables and the CI service account.
def load_kokoro_env
  gfile_dir = ENV["KOKORO_GFILE_DIR"]
  return unless gfile_dir

  filename = "#{gfile_dir}/ruby_env_vars.json"
  raise "#{filename} is not a file" unless File.file? filename
  JSON.parse(File.read(filename)).each { |k, v| ENV[k] ||= v }

  filename = "#{gfile_dir}/secret_manager/ruby-main-ci-service-account"
  raise "#{filename} is not a file" unless File.file? filename
  ENV["GOOGLE_APPLICATION_CREDENTIALS"] = filename

  project_id = JSON.parse(File.read(filename))["project_id"]
  return unless project_id
  puts "Inferred project_id from keyfile: #{project_id}"
  ENV["GOOGLE_CLOUD_PROJECT"] ||= project_id
end

desc "Run samples tests"
task :samples do
  # The samples have their own Gemfile, so leave the root bundle first.
  Bundler.with_unbundled_env do
    load_kokoro_env
    puts "Updating samples bundle ..."
    sh "bundle", "install", chdir: "samples"
    puts "Samples tests ..."
    sh "bundle", "exec", "ruby", "-I../lib", "-Iacceptance", "-e",
       "Dir.glob('acceptance/*_test.rb').each{|f| require File.expand_path(f)}", chdir: "samples"
  end
end

desc "Run CI checks"
task ci: ["test", "integration", "spec", "rubocop", "yardoc", "build", "linkinator"]
