# -*- ruby -*-
require "bundler/gem_tasks"

task :ci do
  sh "bundle exec rspec"
end

# build, release:guard_clean and release:rubygem_push are the upstream
# release task minus the git push.
task :ci_release => ['generate_rubygems_credentials', 'build', 'release:guard_clean', 'release:rubygem_push']

task :generate_rubygems_credentials do
  require 'base64'
  GEM_CREDENTIALS = ENV['HOME'] + '/.gem/credentials'
  b64_authorization = Base64.encode64("#{ENV.fetch('ARTIFACTORY_USERNAME')}:#{ENV.fetch('ARTIFACTORY_PASSWORD')}")
  open(GEM_CREDENTIALS, 'w') do |f|
    f.puts "---\n:rubygems_api_key: Basic #{b64_authorization}\n"
  end
  File.chmod 0600, GEM_CREDENTIALS
end
# end LiveRamp Jenkins CI changes

namespace :kokoro do
  task :load_env_vars do
    service_account = "#{ENV['KOKORO_GFILE_DIR']}/service-account.json"
    ENV["GOOGLE_APPLICATION_CREDENTIALS"] = service_account
    filename = "#{ENV['KOKORO_GFILE_DIR']}/env_vars.json"
    env_vars = JSON.parse File.read(filename)
    env_vars.each { |k, v| ENV[k] = v }
  end

  task :presubmit do
    Rake::Task["ci"].invoke
  end

  task :continuous do
    Rake::Task["ci"].invoke
  end

  task :nightly do
    Rake::Task["ci"].invoke
  end

  task :release do
    version = "0.1.0"
    Bundler.with_clean_env do
      version = `bundle exec gem list`
                .split("\n").select { |line| line.include? "googleauth" }
                .first.split("(").last.split(")").first || "0.1.0"
    end
    Rake::Task["kokoro:load_env_vars"].invoke
    Rake::Task["release"].invoke "v/#{version}"
  end
end

def header str, token = "#"
  line_length = str.length + 8
  puts ""
  puts token * line_length
  puts "#{token * 3} #{str} #{token * 3}"
  puts token * line_length
  puts ""
end
