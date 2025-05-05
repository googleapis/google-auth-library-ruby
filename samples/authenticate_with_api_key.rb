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

# [START apikeys_authenticate_api_key]
require "googleauth"
require "google/cloud/language/v1"

def authenticate_with_api_key api_key_string
  # Authenticates with an API key for Google Language service.
  #
  # TODO(Developer): Uncomment the following line and set the value before running this sample.
  #
  # api_key_string = "mykey12345"
  #
  # Note: You can also set the API key via environment variable:
  #   export GOOGLE_API_KEY=your-api-key
  # and use Google::Auth::APIKeyCredentials.from_env method to load it.
  # Example:
  #   credentials = Google::Auth::APIKeyCredentials.from_env
  #   if credentials.nil?
  #     puts "No API key found in environment"
  #     exit
  #   end

  # Initialize API key credentials using the class factory method
  credentials = Google::Auth::APIKeyCredentials.make_creds api_key: api_key_string

  # Initialize the Language Service client with the API key credentials
  client = Google::Cloud::Language::V1::LanguageService::Client.new do |config|
    config.credentials = credentials
  end

  # Create a document to analyze
  text = "Hello, world!"
  document = {
    content: text,
    type: :PLAIN_TEXT
  }

  # Make a request to analyze the sentiment of the text
  sentiment = client.analyze_sentiment(document: document).document_sentiment

  puts "Text: #{text}"
  puts "Sentiment: #{sentiment.score}, #{sentiment.magnitude}"
  puts "Successfully authenticated using the API key"
end
# [END apikeys_authenticate_api_key]

if $PROGRAM_NAME == __FILE__
  api_key = ARGV[0]
  if api_key.nil? || api_key.empty?
    puts "Usage: ruby #{__FILE__} api-key"
    exit
  end
  authenticate_with_api_key api_key
end
