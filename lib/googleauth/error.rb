module Google
  module Auth
    Error = Class.new(StandardError)

    NOT_FOUND_ERROR = <<~ERROR_MESSAGE.freeze
      Could not load the default credentials. Browse to
      https://developers.google.com/accounts/docs/application-default-credentials
      for more information
    ERROR_MESSAGE
    class DefaultCredentialsNotFoundError < Error
      def initialize
        super(NOT_FOUND_ERROR)
      end
    end
  end
end
