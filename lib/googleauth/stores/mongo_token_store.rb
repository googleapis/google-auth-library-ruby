require 'mongo'
require 'googleauth/token_store'

module Google
  module Auth
    module Stores
      class MongoTokenStore < Google::Auth::TokenStore
        DEFAULT_COLLECTION = 'TokenStore'

        def initialize(options = {})
					collection = options.delete(:collection)
          @mongo = options.delete(:mongo)
          @collection = collection || DEFAULT_COLLECTION
        end

        # (see Google::Auth::Stores::TokenStore#load)
        def load(id)
          ans = @mongo[:TokenStore].find(:_id => id).to_a
          ans.one? ? ans[0][:token] : nil
        end

        # (see Google::Auth::Stores::TokenStore#store)
        def store(id, token)
          @mongo[:TokenStore].update_one({_id: id}, {_id: id, token: token}, {upsert: true})
        end

        # (see Google::Auth::Stores::TokenStore#delete)
        def delete(id)
          @mongo[:TokenStore].delete_one(:_id => id)
        end
      end
    end
  end
end
