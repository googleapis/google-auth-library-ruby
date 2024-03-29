# Copyright 2022 Google LLC
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

expand :minitest do |t|
  t.name = "test"
  t.libs = ["lib", "samples"]
  t.use_bundler on_missing: :install, gemfile_path: "samples/Gemfile"
  t.files = "samples/acceptance/*_test.rb"
end

desc "Run samples tests"

include :exec
include :terminal, styled: true

def run
  require "json"
  require "repo_context"
  RepoContext.load_kokoro_env

  Dir.chdir context_directory
  
  puts "Samples tests ...", :bold, :cyan
  exec_tool ["samples", "test"], name: "Samples tests"
end
