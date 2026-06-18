# A simple GCE Metadata Server proxy that intercepts email requests and simulates a failure (404).
# It forwards all other requests to the real GCE Metadata Server at 169.254.169.254.

require 'webrick'
require 'net/http'

server = WEBrick::HTTPServer.new(Port: 8080)

server.mount_proc '/' do |req, res|
  # If the request is for the service account email, return 404 to simulate failure.
  if req.path.include?('/computeMetadata/v1/instance/service-accounts/default/email')
    res.status = 404
    res.body = "Not Found"
    puts "[Mock Metadata Server] Intercepted email request -> Returned 404 (Simulated Failure)"
  else
    # Proxy all other requests (like token fetching) to the real GCE metadata server
    uri = URI("http://169.254.169.254#{req.path}")
    
    # Reconstruct the proxy request
    http_req = Net::HTTP::Get.new(uri)
    req.header.each do |k, v|
      http_req[k] = v.join(',') unless k.downcase == 'host'
    end
    # Ensure Google metadata header is set
    http_req['Metadata-Flavor'] = 'Google'
    
    begin
      real_res = Net::HTTP.start(uri.hostname, uri.port) do |http|
        http.request(http_req)
      end
      
      res.status = real_res.code.to_i
      real_res.header.each_header do |k, v|
        res[k] = v unless k.downcase == 'transfer-encoding'
      end
      res.body = real_res.body
      puts "[Mock Metadata Server] Proxied request: #{req.path} -> Status #{real_res.code}"
    rescue => e
      res.status = 500
      res.body = e.message
      puts "[Mock Metadata Server] Error proxying request: #{e.message}"
    end
  end
end

trap 'INT' do server.shutdown end
server.start
