# Copyright 2025 Google LLC
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

require_relative "helper"
require_relative "../lib/googleauth/errors"

describe Google::Auth::Error do
  it "can be included in custom errors" do
    custom_error = Class.new(StandardError) do
      include Google::Auth::Error
    end
    
    error = custom_error.new("Custom error message")
    _(error).must_be_kind_of Google::Auth::Error
    _(error.message).must_equal "Custom error message"
  end
end

describe Google::Auth::DetailedError do
  it "can be included in custom errors" do
    custom_error = Class.new(StandardError) do
      include Google::Auth::DetailedError
    end
    
    error = custom_error.new("Custom error message")
    _(error).must_be_kind_of Google::Auth::DetailedError
    _(error).must_be_kind_of Google::Auth::Error
    _(error.message).must_equal "Custom error message"
  end
  
  it "provides a with_details factory method on including classes" do
    custom_error = Class.new(StandardError) do
      include Google::Auth::DetailedError
    end
    
    error = custom_error.with_details("Custom error message", 
                                      credential_type_name: "TestCredential",
                                      principal: "test-principal@example.com")
    
    _(error).must_be_kind_of Google::Auth::DetailedError
    _(error.message).must_equal "Custom error message"
    _(error.credential_type_name).must_equal "TestCredential"
    _(error.principal).must_equal "test-principal@example.com"
  end
end

describe Google::Auth::InitializationError do
  it "is a StandardError" do
    error = Google::Auth::InitializationError.new("Init error")
    _(error).must_be_kind_of StandardError
  end
  
  it "includes the Error module" do
    error = Google::Auth::InitializationError.new("Init error")
    _(error).must_be_kind_of Google::Auth::Error
  end
end

describe Google::Auth::CredentialsError do
  it "is a StandardError" do
    error = Google::Auth::CredentialsError.new("Credential error")
    _(error).must_be_kind_of StandardError
  end
  
  it "includes the DetailedError module" do
    error = Google::Auth::CredentialsError.new("Credential error")
    _(error).must_be_kind_of Google::Auth::DetailedError
  end
end

describe Google::Auth::AuthorizationError do
  it "is a Signet::AuthorizationError" do
    error = Google::Auth::AuthorizationError.new("Auth error")
    _(error).must_be_kind_of Signet::AuthorizationError
  end
  
  it "includes the DetailedError module" do
    error = Google::Auth::AuthorizationError.new("Auth error")
    _(error).must_be_kind_of Google::Auth::DetailedError
  end
  
  it "can be created with detailed information" do
    error = Google::Auth::AuthorizationError.with_details(
      "Failed to authorize request",
      credential_type_name: "Google::Auth::ServiceAccountCredentials", 
      principal: "service-account@example.com"
    )
    
    _(error.message).must_equal "Failed to authorize request"
    _(error.credential_type_name).must_equal "Google::Auth::ServiceAccountCredentials"
    _(error.principal).must_equal "service-account@example.com"
  end
end