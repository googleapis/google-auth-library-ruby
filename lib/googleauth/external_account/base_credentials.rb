# Copyright 2023 Google, Inc.
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
# limitations under the License.require "time"

require "googleauth/base_client"
require "googleauth/helpers/connection"
require "googleauth/oauth2/sts_client"

module Google
  # Module Auth provides classes that provide Google-specific authorization
  # used to access Google APIs.
  module Auth
    # Authenticates requests using External Account credentials, such
    # as those provided by the AWS provider.
    module ExternalAccount
      # Authenticates requests using External Account credentials, such
      # as those provided by the AWS provider.
      module BaseCredentials
        # Contains all methods needed for all external account credentials.
        # Other credentials should call `base_setup` during initialization
        # And should define the :retrieve_subject_token method

        # External account JSON type identifier.
        EXTERNAL_ACCOUNT_JSON_TYPE = "external_account".freeze
        # The token exchange grant_type used for exchanging credentials.
        STS_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange".freeze
        # The token exchange requested_token_type. This is always an access_token.
        STS_REQUESTED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token".freeze
        # Cloud resource manager URL used to retrieve project information.
        CLOUD_RESOURCE_MANAGER = "https://cloudresourcemanager.googleapis.com/v1/projects/".freeze
        # Default IAM_SCOPE
        IAM_SCOPE = ["https://www.googleapis.com/auth/iam".freeze].freeze

        include Google::Auth::BaseClient
        include Helpers::Connection

        attr_reader :expires_at
        attr_accessor :access_token

        def expires_within? seconds
          # This method is needed for BaseClient
          @expires_at && @expires_at - Time.now.utc < seconds
        end

        def expires_at= new_expires_at
          @expires_at = normalize_timestamp new_expires_at
        end

        def fetch_access_token! _options = {}
          # This method is needed for BaseClient
          response = exchange_token

          if @service_account_impersonation_url
            impersonated_response = get_impersonated_access_token response["access_token"]
            self.expires_at = impersonated_response["expireTime"]
            self.access_token = impersonated_response["accessToken"]
          else
            # Extract the expiration time in seconds from the response and calculate the actual expiration time
            # and then save that to the expiry variable.
            self.expires_at = Time.now.utc + response["expires_in"].to_i
            self.access_token = response["access_token"]
          end

          notify_refresh_listeners
        end

        ##
        # Retrieves the project ID corresponding to the workload identity or workforce pool.
        # For workforce pool credentials, it returns the project ID corresponding to the workforce_pool_user_project.
        # When not determinable, None is returned.
        #
        # The resource may not have permission (resourcemanager.projects.get) to
        # call this API or the required scopes may not be selected:
        # https://cloud.google.com/resource-manager/reference/rest/v1/projects/get#authorization-scopes
        #
        # @return [string,nil]
        #     The project ID corresponding to the workload identity pool or workforce pool if determinable.
        #
        def project_id
          return @project_id unless @project_id.nil?
          project_number = self.project_number || @workforce_pool_user_project

          # if we missing either project number or scope, we won't retrieve project_id
          return nil if project_number.nil? || @scope.nil?

          url = "#{CLOUD_RESOURCE_MANAGER}#{project_number}"

          response = connection.get url do |req|
            req.headers["Authorization"] = "Bearer #{@access_token}"
            req.headers["Content-Type"] = "application/json"
          end

          if response.status == 200
            response_data = MultiJson.load response.body, symbolize_names: true
            @project_id = response_data[:projectId]
          end

          @project_id
        end

        ##
        # Retrieve the project number corresponding to workload identity pool
        # STS audience pattern:
        #     `//iam.googleapis.com/projects/$PROJECT_NUMBER/locations/...`
        #
        # @return [string, nil]
        #
        def project_number
          segments = @audience.split "/"
          idx = segments.index "projects"
          return nil if idx.nil? || idx + 1 == segments.size
          segments[idx + 1]
        end

        private

        def token_type
          # This method is needed for BaseClient
          :access_token
        end

        def base_setup options
          self.default_connection = options[:connection]

          @audience = options[:audience]
          @scope = options[:scope] || IAM_SCOPE
          @subject_token_type = options[:subject_token_type]
          @token_url = options[:token_url]
          @service_account_impersonation_url = options[:service_account_impersonation_url]
          @service_account_impersonation_options = options[:service_account_impersonation_options] || {}
          @client_id = options[:client_id]
          @client_secret = options[:client_secret]
          @quota_project_id = options[:quota_project_id]
          @project_id = nil
          @workforce_pool_user_project = [:workforce_pool_user_project]

          @expires_at = nil
          @access_token = nil

          @sts_client = Google::Auth::OAuth2::STSClient.new(
            token_exchange_endpoint: @token_url,
            connection: default_connection
          )
        end

        def normalize_timestamp time
          case time
          when NilClass
            nil
          when Time
            time
          when String
            Time.parse time
          else
            raise "Invalid time value #{time}"
          end
        end

        def exchange_token
          @sts_client.exchange_token(
            audience: @audience,
            grant_type: STS_GRANT_TYPE,
            subject_token: retrieve_subject_token!,
            subject_token_type: @subject_token_type,
            scopes: @service_account_impersonation_url ? IAM_SCOPE : @scope,
            requested_token_type: STS_REQUESTED_TOKEN_TYPE
          )
        end

        def get_impersonated_access_token token, _options = {}
          response = connection.post @service_account_impersonation_url do |req|
            req.headers["Authorization"] = "Bearer #{token}"
            req.headers["Content-Type"] = "application/json"
            req.body = MultiJson.dump({ scope: @scope })
          end

          if response.status != 200
            raise "Service account impersonation failed with status #{response.status}"
          end

          MultiJson.load response.body
        end

        def retrieve_subject_token!
          raise NotImplementedError
        end
      end
    end
  end
end
