# frozen_string_literal: true

# Copyright 2021 Google LLC
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

expand :clean, paths: :gitignore

tool "spec" do
  desc "Run RSpec tests"
  include :exec
  def run
    exec ["bundle", "exec", "rspec"]
  end
end

tool "test" do
  desc "Run unit tests"
  include :exec
  def run
    exec ["bundle", "exec", "ruby", "-Ilib", "-Itest", "-e", "Dir.glob('test/**/*_test.rb').each{|f| require File.expand_path(f)}"]
  end
end

tool "integration" do
  desc "Run integration tests"
  include :exec
  def run
    exec ["bundle", "exec", "ruby", "-Ilib", "-Iintegration", "-e", "Dir.glob('integration/**/*_test.rb').each{|f| require File.expand_path(f)}"]
  end
end

expand :rubocop, bundler: true

expand :yardoc do |t|
  t.generate_output_flag = true
  # t.fail_on_warning = true
  t.use_bundler
end
alias_tool :yard, :yardoc

expand :gem_build

expand :gem_build, name: "install", install_gem: true
