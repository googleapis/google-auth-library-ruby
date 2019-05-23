# Copyright 2014, Google Inc.
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

require 'active_record'
require 'googleauth/token_store'

module Google
  module Auth
    module Stores
      # Simple model for storing tokens
      class GoogleAuthToken < ActiveRecord::Base
        validates :user_id, presence: true
        validates :token, presence: true
      end

      # Implementation of user token storage using ActiveRecord.
      class ActiveRecordTokenStore < Google::Auth::TokenStore
        def initialize(*)
        end

        # (see Google::Auth::Stores::TokenStore#load)
        def load(id)
          entry = GoogleAuthToken.find_by(user_id: id)
          return nil if entry.nil?
          entry.token
        end

        # (see Google::Auth::Stores::TokenStore#store)
        def store(id, token)
          entry = GoogleAuthToken.find_or_initialize_by(user_id: id)
          entry.update(token: token)
        end

        # (see Google::Auth::Stores::TokenStore#delete)
        def delete(id)
          entry = GoogleAuthToken.find_by(user_id: id)
          entry.destroy unless entry.nil?
        end
      end
    end
  end
end
