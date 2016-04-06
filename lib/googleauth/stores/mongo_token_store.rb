require 'mongo'
require 'googleauth/token_store'

module Google
  module Auth
    module Stores
      # Implementation of user token storage backed by Mongo. Tokens
      # are stored in 'TokenStore' collection, in a document which look
      # like this: { _id: ID, token: TOKEN}
      class MongoTokenStore < Google::Auth::TokenStore
        DEFAULT_COLLECTION = 'TokenStore'

        # Create a new store with the supplied mongo client.
        #
        # @param [Mongo::Client] mongo
        #  Initialized mongo client to connect to.
        # @param [String] collection
        #  Collection name for mongo. Defaults to 'TokenStore'
        def initialize(options = {})
					collection = options.delete(:collection)
          @mongo = options.delete(:mongo)
          @collection = collection || DEFAULT_COLLECTION
        end

        # (see Google::Auth::Stores::TokenStore#load)
        def load(id)
          ans = @mongo[@collection].find({_id: id}, {limit: 1, projection: {_id: 0, token: 1}}).to_a
          ans.any? ? ans[0][:token] : nil
        end

        # (see Google::Auth::Stores::TokenStore#store)
        def store(id, token)
          @mongo[@collection].update_one({_id: id}, {_id: id, token: token}, {upsert: true})
        end

        # (see Google::Auth::Stores::TokenStore#delete)
        def delete(id)
          @mongo[@collection].delete_one({_id: id})
        end
      end
    end
  end
end
