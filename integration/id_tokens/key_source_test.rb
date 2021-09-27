# Copyright 2020 Google LLC
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

require "helper"

describe Google::Auth::IDTokens do
  describe "key source" do
    let(:legacy_oidc_key_source) {
      Google::Auth::IDTokens::X509CertHttpKeySource.new "https://www.googleapis.com/oauth2/v1/certs"
    }
    let(:oidc_key_source) { Google::Auth::IDTokens.oidc_key_source }
    let(:iap_key_source) { Google::Auth::IDTokens.iap_key_source }

    it "Gets real keys from the OAuth2 V1 cert URL" do
      keys = legacy_oidc_key_source.refresh_keys
      refute_empty keys
      keys.each do |key|
        assert_kind_of OpenSSL::PKey::RSA, key.key
        refute key.key.private?
        assert_equal "RS256", key.algorithm
      end
    end

    it "Gets real keys from the OAuth2 V3 cert URL" do
      keys = oidc_key_source.refresh_keys
      refute_empty keys
      keys.each do |key|
        assert_kind_of OpenSSL::PKey::RSA, key.key
        refute key.key.private?
        assert_equal "RS256", key.algorithm
      end
    end

    it "Gets the same keys from the OAuth2 V1 and V3 cert URLs" do
      keys_v1 = legacy_oidc_key_source.refresh_keys.map(&:key).map(&:export).sort
      keys_v3 = oidc_key_source.refresh_keys.map(&:key).map(&:export).sort
      assert_equal keys_v1, keys_v3
    end

    it "Gets real keys from the IAP public key URL" do
      keys = iap_key_source.refresh_keys
      refute_empty keys
      keys.each do |key|
        assert_kind_of OpenSSL::PKey::EC, key.key
        assert_equal "ES256", key.algorithm
      end
    end
  end
end
