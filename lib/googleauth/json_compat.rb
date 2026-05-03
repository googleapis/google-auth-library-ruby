# frozen_string_literal: true

require "multi_json"

# MultiJSON was introduced as the canonical all-caps constant in multi_json 1.21.0,
# along with parse/generate (replacing load/dump) and symbolize_names: (replacing
# symbolize_keys:). For older versions we define a shim so all call sites can use
# the 1.21+ API uniformly.
# To be removed when we drop support for multi_json < 1.21.0
unless defined?(::MultiJSON)
  module ::MultiJSON # rubocop:disable Style/Documentation
    def self.parse str, opts = {}
      opts[:symbolize_keys] = opts.delete(:symbolize_names) if opts.key? :symbolize_names
      MultiJson.load str, opts
    end

    def self.generate obj, opts = {}
      MultiJson.dump obj, opts
    end

    ParseError = MultiJson::ParseError
  end
end
