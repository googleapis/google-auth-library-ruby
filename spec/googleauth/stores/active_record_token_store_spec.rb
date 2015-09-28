# Copyright 2015, Google Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above
# copyright notice, this list of conditions and the following disclaimer
# in the documentation and/or other materials provided with the
# distribution.
#     * Neither the name of Google Inc. nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

spec_dir = File.expand_path(File.join(File.dirname(__FILE__)))
$LOAD_PATH.unshift(spec_dir)
$LOAD_PATH.uniq!

require 'googleauth'
require 'googleauth/stores/active_record_token_store'
require 'spec_helper'
require 'googleauth/stores/store_examples'
require 'active_record'

module FakeFS
  class File
    # FakeFS doesn't implement. And since we don't need to actually lock, just stub out...
    def flock(*)
    end
  end
end

describe Google::Auth::Stores::ActiveRecordTokenStore do
  # Set up an in-memory DB for testing
  before(:context) do
    ActiveRecord::Base.establish_connection adapter: "sqlite3", database: ":memory:"
    ActiveRecord::Schema.define do
      self.verbose = false
      create_table :google_auth_tokens do |t|
        t.string :user_id
        t.string :token
      end
      add_index :google_auth_tokens, :user_id
    end
  end
  
  let(:store) do
    Google::Auth::Stores::ActiveRecordTokenStore.new
  end
    
  it_behaves_like 'token store' 
end

