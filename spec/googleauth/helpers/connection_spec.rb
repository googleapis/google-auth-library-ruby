# Copyright 2026 Google LLC
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

require "spec_helper"
require "googleauth"

describe Google::Auth::Helpers::Connection do
  describe ".connection_for" do
    let(:global_connection) { Faraday.new }
    let(:custom_connection) { Faraday.new }

    before do
      allow(described_class).to receive(:connection).and_return(global_connection)
    end

    context "when client responds to build_default_connection" do
      let(:client) do
        double("client", build_default_connection: custom_connection)
      end

      it "returns the result of build_default_connection" do
        expect(described_class.connection_for(client)).to eq(custom_connection)
      end
    end

    context "when client responds to connection" do
      let(:client) do
        double("client", connection: custom_connection)
      end

      it "returns the result of connection" do
        expect(described_class.connection_for(client)).to eq(custom_connection)
      end
    end

    context "when client responds to both" do
      let(:client) do
        double("client",
               build_default_connection: custom_connection,
               connection: double("fallback_connection"))
      end

      it "prioritizes build_default_connection" do
        expect(described_class.connection_for(client)).to eq(custom_connection)
      end
    end

    context "when client responds to neither" do
      let(:client) { double("client") }

      it "falls back to global connection" do
        expect(described_class.connection_for(client)).to eq(global_connection)
      end
    end
  end
end
