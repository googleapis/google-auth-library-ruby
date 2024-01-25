# Copyright 2015 Google, Inc.
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

spec_dir = File.expand_path File.join(File.dirname(__FILE__))
$LOAD_PATH.unshift spec_dir
$LOAD_PATH.uniq!

require "apply_auth_examples"
require "faraday"
require "googleauth/compute_engine"
require "spec_helper"

describe Google::Auth::GCECredentials do
  MD_ACCESS_URI = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token".freeze
  MD_ID_URI = "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://pubsub.googleapis.com/&format=full".freeze
  GCECredentials = Google::Auth::GCECredentials

  before :example do
    Google::Cloud.env.compute_smbios.override_product_name = "Google Compute Engine"
    GCECredentials.reset_cache
    @client = GCECredentials.new
    @id_client = GCECredentials.new target_audience: "https://pubsub.googleapis.com/"
  end

  after :example do
    Google::Cloud.env.compute_smbios.override_product_name = nil
  end

  def make_auth_stubs opts
    universe_stub = stub_request(:get, "http://169.254.169.254/computeMetadata/v1/universe/universe_domain")
      .with(headers: { "Metadata-Flavor" => "Google" })
    if !defined?(@universe_domain) || !@universe_domain
      universe_stub.to_return body: "", status:  404, headers: {"Metadata-Flavor" => "Google" }
    elsif @universe_domain.is_a? Class
      universe_stub.to_raise @universe_domain
    else
      universe_stub.to_return body: @universe_domain, status: 200, headers: {"Metadata-Flavor" => "Google" }
    end
    if opts[:access_token]
      body = MultiJson.dump("access_token" => opts[:access_token],
                            "token_type"   => "Bearer",
                            "expires_in"   => 3600)

      uri = MD_ACCESS_URI
      uri += "?scopes=#{Array(opts[:scope]).join ','}" if opts[:scope]

      stub_request(:get, uri)
        .with(headers: { "Metadata-Flavor" => "Google" })
        .to_return(body:    body,
                   status:  200,
                   headers: { "Content-Type" => "application/json", "Metadata-Flavor" => "Google" })
    elsif opts[:id_token]
      stub_request(:get, MD_ID_URI)
        .with(headers: { "Metadata-Flavor" => "Google" })
        .to_return(body:    opts[:id_token],
                   status:  200,
                   headers: { "Content-Type" => "text/html", "Metadata-Flavor" => "Google" })
    end
  end

  context "default universe due to 404 from MDS" do
    it_behaves_like "apply/apply! are OK"

    it "sets the universe" do
      make_auth_stubs access_token: "1/abcde"
      @client.fetch_access_token!
      expect(@client.universe_domain).to eq("googleapis.com")
    end

    it "returns a consistent expiry using cached data" do
      make_auth_stubs access_token: "1/abcde"
      @client.fetch_access_token!
      expiry = @client.expires_at
      sleep 1
      @client.fetch_access_token!
      expect(@client.expires_at.to_f).to be_within(0.1).of(expiry.to_f)
    end
  end

  context "default universe due to empty data from MDS" do
    before :example do
      @universe_domain = ""
    end

    it_behaves_like "apply/apply! are OK"

    it "sets the universe" do
      make_auth_stubs access_token: "1/abcde"
      @client.fetch_access_token!
      expect(@client.universe_domain).to eq("googleapis.com")
    end

    it "returns a consistent expiry using cached data" do
      make_auth_stubs access_token: "1/abcde"
      @client.fetch_access_token!
      expiry = @client.expires_at
      sleep 1
      @client.fetch_access_token!
      expect(@client.expires_at.to_f).to be_within(0.1).of(expiry.to_f)
    end
  end

  context "custom universe" do
    before :example do
      @universe_domain = "myuniverse.com"
    end

    it_behaves_like "apply/apply! are OK"

    it "sets the universe" do
      make_auth_stubs access_token: "1/abcde"
      @client.fetch_access_token!
      expect(@client.universe_domain).to eq("myuniverse.com")
    end

    it "supports updating the universe_domain" do
      make_auth_stubs access_token: "1/abcde"
      @client.fetch_access_token!
      @client.universe_domain = "anotheruniverse.com"
      expect(@client.universe_domain).to eq("anotheruniverse.com")
    end
  end

  context "error in universe_domain" do
    before :example do
      @universe_domain = Errno::EHOSTDOWN
    end

    it "results in an error" do
      make_auth_stubs access_token: "1/abcde"
      expect { @client.fetch_access_token! }
        .to raise_error Signet::AuthorizationError
    end
  end

  context "metadata is unavailable" do
    describe "#fetch_access_token" do
      it "should pass scopes when requesting an access token" do
        scopes = ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/bigtable.data"]
        stub = make_auth_stubs access_token: "1/abcdef1234567890", scope: scopes
        @client = GCECredentials.new(scope: scopes)
        @client.fetch_access_token!
        expect(stub).to have_been_requested
      end

      it "should fail if the metadata request returns a 404" do
        stub = stub_request(:get, MD_ACCESS_URI)
               .to_return(status:  404,
                          headers: { "Metadata-Flavor" => "Google" })
        expect { @client.fetch_access_token! }
          .to raise_error Signet::AuthorizationError
        expect(stub).to have_been_requested
      end

      it "should fail if the metadata request returns a 403" do
        stub = stub_request(:get, MD_ACCESS_URI)
                 .to_return(status:  403,
                            headers: { "Metadata-Flavor" => "Google" })
        expect { @client.fetch_access_token! }
          .to raise_error Signet::AuthorizationError
        expect(stub).to have_been_requested.times(6)
      end

      it "should fail if the metadata request returns a 500" do
        stub = stub_request(:get, MD_ACCESS_URI)
                 .to_return(status:  500,
                            headers: { "Metadata-Flavor" => "Google" })
        expect { @client.fetch_access_token! }
          .to raise_error Signet::AuthorizationError
        expect(stub).to have_been_requested.times(6)
      end

      it "should fail if the metadata request returns an unexpected code" do
        stub = stub_request(:get, MD_ACCESS_URI)
               .to_return(status:  503,
                          headers: { "Metadata-Flavor" => "Google" })
        expect { @client.fetch_access_token! }
          .to raise_error Signet::AuthorizationError
        expect(stub).to have_been_requested
      end

      it "should fail with Signet::AuthorizationError if request times out" do
        allow_any_instance_of(Faraday::Connection).to receive(:get)
          .and_raise(Faraday::TimeoutError)
        expect { @client.fetch_access_token! }
          .to raise_error Signet::AuthorizationError
      end

      it "should fail with Signet::AuthorizationError if request fails" do
        allow_any_instance_of(Faraday::Connection).to receive(:get)
          .and_raise(Faraday::ConnectionFailed, nil)
        expect { @client.fetch_access_token! }
          .to raise_error Signet::AuthorizationError
      end
    end

    describe "Fetch ID tokens" do
      it "should pass scopes when requesting an ID token" do
        scopes = ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/bigtable.data"]
        stub = make_auth_stubs id_token: "1/abcdef1234567890", scope: scopes
        @id_client.fetch_access_token!
        expect(stub).to have_been_requested
      end

      it "should fail if the metadata request returns a 404" do
        stub = stub_request(:get, MD_ID_URI)
               .to_return(status:  404,
                          headers: { "Metadata-Flavor" => "Google" })
        expect { @id_client.fetch_access_token! }
          .to raise_error Signet::AuthorizationError
        expect(stub).to have_been_requested
      end

      it "should fail if the metadata request returns a 403" do
        stub = stub_request(:get, MD_ID_URI)
                 .to_return(status:  403,
                            headers: { "Metadata-Flavor" => "Google" })
        expect { @id_client.fetch_access_token! }
          .to raise_error Signet::AuthorizationError
        expect(stub).to have_been_requested.times(6)
      end

      it "should fail if the metadata request returns a 500" do
        stub = stub_request(:get, MD_ID_URI)
                 .to_return(status:  500,
                            headers: { "Metadata-Flavor" => "Google" })
        expect { @id_client.fetch_access_token! }
          .to raise_error Signet::AuthorizationError
        expect(stub).to have_been_requested.times(6)
      end

      it "should fail if the metadata request returns an unexpected code" do
        stub = stub_request(:get, MD_ID_URI)
               .to_return(status:  503,
                          headers: { "Metadata-Flavor" => "Google" })
        expect { @id_client.fetch_access_token! }
          .to raise_error Signet::AuthorizationError
        expect(stub).to have_been_requested
      end

      it "should fail with Signet::AuthorizationError if request times out" do
        allow_any_instance_of(Faraday::Connection).to receive(:get)
          .and_raise(Faraday::TimeoutError)
        expect { @id_client.fetch_access_token! }
          .to raise_error Signet::AuthorizationError
      end

      it "should fail with Signet::AuthorizationError if request fails" do
        allow_any_instance_of(Faraday::Connection).to receive(:get)
          .and_raise(Faraday::ConnectionFailed, nil)
        expect { @id_client.fetch_access_token! }
          .to raise_error Signet::AuthorizationError
      end
    end
  end

  describe "#on_gce?" do
    it "should be true when Metadata-Flavor is Google" do
      stub = stub_request(:get, "http://169.254.169.254")
             .with(headers: { "Metadata-Flavor" => "Google" })
             .to_return(status:  200,
                        headers: { "Metadata-Flavor" => "Google" })
      expect(GCECredentials.on_gce?({}, true)).to eq(true)
      expect(stub).to have_been_requested
    end

    it "should be false when Metadata-Flavor is not Google" do
      stub = stub_request(:get, "http://169.254.169.254")
             .with(headers: { "Metadata-Flavor" => "Google" })
             .to_return(status:  200,
                        headers: { "Metadata-Flavor" => "NotGoogle" })
      expect(GCECredentials.on_gce?({}, true)).to eq(false)
      expect(stub).to have_been_requested
    end

    it "should be false if the response is not 200" do
      stub = stub_request(:get, "http://169.254.169.254")
             .with(headers: { "Metadata-Flavor" => "Google" })
             .to_return(status:  404,
                        headers: { "Metadata-Flavor" => "Google" })
      expect(GCECredentials.on_gce?({}, true)).to eq(false)
      expect(stub).to have_been_requested
    end

    it "should honor GCE_METADATA_HOST environment variable" do
      ENV["GCE_METADATA_HOST"] = "mymetadata.example.com"
      Google::Cloud.env.compute_metadata.reset!
      begin
        stub = stub_request(:get, "http://mymetadata.example.com")
               .with(headers: { "Metadata-Flavor" => "Google" })
               .to_return(status:  200,
                          headers: { "Metadata-Flavor" => "Google" })
        expect(GCECredentials.on_gce?({}, true)).to eq(true)
        expect(stub).to have_been_requested
      ensure
        ENV.delete "GCE_METADATA_HOST"
        Google::Cloud.env.compute_metadata.reset!
      end
    end
  end
end
