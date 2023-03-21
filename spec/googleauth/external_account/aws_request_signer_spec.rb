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
# limitations under the License.

require 'googleauth/external_account/aws_credentials'

describe Google::Auth::ExternalAccount::AwsRequestSigner do
  AwsRequestSigner = Google::Auth::ExternalAccount::AwsRequestSigner

  # Sample AWS security credentials to be used with tests that require a session token.
  ACCESS_KEY_ID = 'ASIARD4OQDT6A77FR3CL'
  SECRET_ACCESS_KEY = 'Y8AfSaucF37G4PpvfguKZ3/l7Id4uocLXxX0+VTx'
  TOKEN = 'IQoJb3JpZ2luX2VjEIz//////////wEaCXVzLWVhc3QtMiJGMEQCIH7MHX/Oy/OB8OlLQa9GrqU1B914+iMikqWQW7vPCKlgAiA/Lsv8Jcafn14owfxXn95FURZNKaaphj0ykpmS+Ki+CSq0AwhlEAAaDDA3NzA3MTM5MTk5NiIMx9sAeP1ovlMTMKLjKpEDwuJQg41/QUKx0laTZYjPlQvjwSqS3OB9P1KAXPWSLkliVMMqaHqelvMF/WO/glv3KwuTfQsavRNs3v5pcSEm4SPO3l7mCs7KrQUHwGP0neZhIKxEXy+Ls//1C/Bqt53NL+LSbaGv6RPHaX82laz2qElphg95aVLdYgIFY6JWV5fzyjgnhz0DQmy62/Vi8pNcM2/VnxeCQ8CC8dRDSt52ry2v+nc77vstuI9xV5k8mPtnaPoJDRANh0bjwY5Sdwkbp+mGRUJBAQRlNgHUJusefXQgVKBCiyJY4w3Csd8Bgj9IyDV+Azuy1jQqfFZWgP68LSz5bURyIjlWDQunO82stZ0BgplKKAa/KJHBPCp8Qi6i99uy7qh76FQAqgVTsnDuU6fGpHDcsDSGoCls2HgZjZFPeOj8mmRhFk1Xqvkbjuz8V1cJk54d3gIJvQt8gD2D6yJQZecnuGWd5K2e2HohvCc8Fc9kBl1300nUJPV+k4tr/A5R/0QfEKOZL1/k5lf1g9CREnrM8LVkGxCgdYMxLQow1uTL+QU67AHRRSp5PhhGX4Rek+01vdYSnJCMaPhSEgcLqDlQkhk6MPsyT91QMXcWmyO+cAZwUPwnRamFepuP4K8k2KVXs/LIJHLELwAZ0ekyaS7CptgOqS7uaSTFG3U+vzFZLEnGvWQ7y9IPNQZ+Dffgh4p3vF4J68y9049sI6Sr5d5wbKkcbm8hdCDHZcv4lnqohquPirLiFQ3q7B17V9krMPu3mz1cg4Ekgcrn/E09NTsxAqD8NcZ7C7ECom9r+X3zkDOxaajW6hu3Az8hGlyylDaMiFfRbBJpTIlxp7jfa7CxikNgNtEKLH9iCzvuSg2vhA=='
  # To avoid json.dumps() differing behavior from one version to other,
  # the JSON payload is hardcoded.
  REQUEST_PARAMS = '{"KeySchema":[{"KeyType":"HASH","AttributeName":"Id"}],"TableName":"TestTable","AttributeDefinitions":[{"AttributeName":"Id","AttributeType":"S"}],"ProvisionedThroughput":{"WriteCapacityUnits":5,"ReadCapacityUnits":5}}'

  TEST_FIXTURES = [
    # GET request (AWS botocore tests).
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-vanilla.req
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-vanilla.sreq
    {
        region: 'us-east-1',
        time: '2011-09-09T23:36:00Z',
        credentials: {
            access_key_id: 'AKIDEXAMPLE',
            secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        },
        original_request: {
            method: 'GET',
            url: 'https://host.foo.com',
            headers: {'date': 'Mon, 09 Sep 2011 23:36:00 GMT'},
        },
        signed_request: {
            url: 'https://host.foo.com',
            method: 'GET',
            headers: {
                'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=b27ccfbfa7df52a200ff74193ca6e32d4b48b8856fab7ebf1c595d0670a7e470',
                'host': 'host.foo.com',
                'date': 'Mon, 09 Sep 2011 23:36:00 GMT',
            },
        },
    },
    # GET request with relative path (AWS botocore tests).
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-relative-relative.req
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-relative-relative.sreq
    {
        region: 'us-east-1',
        time: '2011-09-09T23:36:00Z',
        credentials: {
            access_key_id: 'AKIDEXAMPLE',
            secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        },
        original_request: {
            method: 'GET',
            url: 'https://host.foo.com/foo/bar/../..',
            headers: {'date': 'Mon, 09 Sep 2011 23:36:00 GMT'},
        },
        signed_request: {
            url: 'https://host.foo.com/foo/bar/../..',
            method: 'GET',
            headers: {
                'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=b27ccfbfa7df52a200ff74193ca6e32d4b48b8856fab7ebf1c595d0670a7e470',
                'host': 'host.foo.com',
                'date': 'Mon, 09 Sep 2011 23:36:00 GMT',
            },
        },
    },
    # GET request with /./ path (AWS botocore tests).
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-slash-dot-slash.req
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-slash-dot-slash.sreq
    {
        region: 'us-east-1',
        time: '2011-09-09T23:36:00Z',
        credentials: {
            access_key_id: 'AKIDEXAMPLE',
            secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        },
        original_request: {
            method: 'GET',
            url: 'https://host.foo.com/./',
            headers: {'date': 'Mon, 09 Sep 2011 23:36:00 GMT'},
        },
        signed_request: {
            url: 'https://host.foo.com/./',
            method: 'GET',
            headers: {
                'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=b27ccfbfa7df52a200ff74193ca6e32d4b48b8856fab7ebf1c595d0670a7e470',
                'host': 'host.foo.com',
                'date': 'Mon, 09 Sep 2011 23:36:00 GMT',
            },
        },
    },
    # GET request with pointless dot path (AWS botocore tests).
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-slash-pointless-dot.req
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-slash-pointless-dot.sreq
    {
        region: 'us-east-1',
        time: '2011-09-09T23:36:00Z',
        credentials: {
            access_key_id: 'AKIDEXAMPLE',
            secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        },
        original_request: {
            method: 'GET',
            url: 'https://host.foo.com/./foo',
            headers: {'date': 'Mon, 09 Sep 2011 23:36:00 GMT'},
        },
        signed_request: {
            url: 'https://host.foo.com/./foo',
            method: 'GET',
            headers: {
                'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=910e4d6c9abafaf87898e1eb4c929135782ea25bb0279703146455745391e63a',
                'host': 'host.foo.com',
                'date': 'Mon, 09 Sep 2011 23:36:00 GMT',
            },
        },
    },
    # GET request with utf8 path (AWS botocore tests).
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-utf8.req
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-utf8.sreq
    {
        region: 'us-east-1',
        time: '2011-09-09T23:36:00Z',
        credentials: {
            access_key_id: 'AKIDEXAMPLE',
            secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        },
        original_request: {
            method: 'GET',
            url: 'https://host.foo.com/%E1%88%B4',
            headers: {'date': 'Mon, 09 Sep 2011 23:36:00 GMT'},
        },
        signed_request: {
            url: 'https://host.foo.com/%E1%88%B4',
            method: 'GET',
            headers: {
                'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=8d6634c189aa8c75c2e51e106b6b5121bed103fdb351f7d7d4381c738823af74',
                'host': 'host.foo.com',
                'date': 'Mon, 09 Sep 2011 23:36:00 GMT',
            },
        },
    },
    # GET request with duplicate query key (AWS botocore tests).
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-vanilla-query-order-key-case.req
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-vanilla-query-order-key-case.sreq
    {
        region: 'us-east-1',
        time: '2011-09-09T23:36:00Z',
        credentials: {
            access_key_id: 'AKIDEXAMPLE',
            secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        },
        original_request: {
            method: 'GET',
            url: 'https://host.foo.com/?foo=Zoo&foo=aha',
            headers: {'date': 'Mon, 09 Sep 2011 23:36:00 GMT'},
        },
        signed_request: {
            url: 'https://host.foo.com/?foo=Zoo&foo=aha',
            method: 'GET',
            headers: {
                'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=be7148d34ebccdc6423b19085378aa0bee970bdc61d144bd1a8c48c33079ab09',
                'host': 'host.foo.com',
                'date': 'Mon, 09 Sep 2011 23:36:00 GMT',
            },
        },
    },
    # GET request with duplicate out of order query key (AWS botocore tests).
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-vanilla-query-order-value.req
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-vanilla-query-order-value.sreq
    {
        region: 'us-east-1',
        time: '2011-09-09T23:36:00Z',
        credentials: {
            access_key_id: 'AKIDEXAMPLE',
            secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        },
        original_request: {
            method: 'GET',
            url: 'https://host.foo.com/?foo=b&foo=a',
            headers: {'date': 'Mon, 09 Sep 2011 23:36:00 GMT'},
        },
        signed_request: {
            url: 'https://host.foo.com/?foo=b&foo=a',
            method: 'GET',
            headers: {
                'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=feb926e49e382bec75c9d7dcb2a1b6dc8aa50ca43c25d2bc51143768c0875acc',
                'host': 'host.foo.com',
                'date': 'Mon, 09 Sep 2011 23:36:00 GMT',
            },
        },
    },
    # GET request with utf8 query (AWS botocore tests).
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-vanilla-ut8-query.req
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-vanilla-ut8-query.sreq
    {
        region: 'us-east-1',
        time: '2011-09-09T23:36:00Z',
        credentials: {
            access_key_id: 'AKIDEXAMPLE',
            secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        },
        original_request: {
            method: 'GET',
            url: "https://host.foo.com/?#{CGI.unescape('%E1%88%B4')}=bar",
            headers: {'date': 'Mon, 09 Sep 2011 23:36:00 GMT'},
        },
        signed_request: {
            url: "https://host.foo.com/?#{CGI.unescape('%E1%88%B4')}=bar",
            method: 'GET',
            headers: {
                'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=6fb359e9a05394cc7074e0feb42573a2601abc0c869a953e8c5c12e4e01f1a8c',
                'host': 'host.foo.com',
                'date': 'Mon, 09 Sep 2011 23:36:00 GMT',
            },
        },
    },
    # POST request with sorted headers (AWS botocore tests).
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/post-header-key-sort.req
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/post-header-key-sort.sreq
    {
        region: 'us-east-1',
        time: '2011-09-09T23:36:00Z',
        credentials: {
            access_key_id: 'AKIDEXAMPLE',
            secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        },
        original_request: {
            method: 'POST',
            url: 'https://host.foo.com/',
            headers: {'date': 'Mon, 09 Sep 2011 23:36:00 GMT', 'ZOO': 'zoobar'},
        },
        signed_request: {
            url: 'https://host.foo.com/',
            method: 'POST',
            headers: {
                'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host;zoo, Signature=b7a95a52518abbca0964a999a880429ab734f35ebbf1235bd79a5de87756dc4a',
                'host': 'host.foo.com',
                'date': 'Mon, 09 Sep 2011 23:36:00 GMT',
                'ZOO': 'zoobar',
            },
        },
    },
    # POST request with upper case header value from AWS Python test harness.
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/post-header-value-case.req
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/post-header-value-case.sreq
    {
        region: 'us-east-1',
        time: '2011-09-09T23:36:00Z',
        credentials: {
            access_key_id: 'AKIDEXAMPLE',
            secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        },
        original_request: {
            method: 'POST',
            url: 'https://host.foo.com/',
            headers: {'date': 'Mon, 09 Sep 2011 23:36:00 GMT', 'zoo': 'ZOOBAR'},
        },
        signed_request: {
            url: 'https://host.foo.com/',
            method: 'POST',
            headers: {
                'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host;zoo, Signature=273313af9d0c265c531e11db70bbd653f3ba074c1009239e8559d3987039cad7',
                'host': 'host.foo.com',
                'date': 'Mon, 09 Sep 2011 23:36:00 GMT',
                'zoo': 'ZOOBAR',
            },
        },
    },
    # POST request with header and no body (AWS botocore tests).
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-header-value-trim.req
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/get-header-value-trim.sreq
    {
        region: 'us-east-1',
        time: '2011-09-09T23:36:00Z',
        credentials: {
            access_key_id: 'AKIDEXAMPLE',
            secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        },
        original_request: {
            method: 'POST',
            url: 'https://host.foo.com/',
            headers: {'date': 'Mon, 09 Sep 2011 23:36:00 GMT', 'p': 'phfft'},
        },
        signed_request: {
            url: 'https://host.foo.com/',
            method: 'POST',
            headers: {
                'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host;p, Signature=debf546796015d6f6ded8626f5ce98597c33b47b9164cf6b17b4642036fcb592',
                'host': 'host.foo.com',
                'date': 'Mon, 09 Sep 2011 23:36:00 GMT',
                'p': 'phfft',
            },
        },
    },
    # POST request with body and no header (AWS botocore tests).
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/post-x-www-form-urlencoded.req
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/post-x-www-form-urlencoded.sreq
    {
        region: 'us-east-1',
        time: '2011-09-09T23:36:00Z',
        credentials: {
            access_key_id: 'AKIDEXAMPLE',
            secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        },
        original_request: {
            method: 'POST',
            url: 'https://host.foo.com/',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'date': 'Mon, 09 Sep 2011 23:36:00 GMT',
            },
            data: 'foo=bar',
        },
        signed_request: {
            url: 'https://host.foo.com/',
            method: 'POST',
            headers: {
                'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=content-type;date;host, Signature=5a15b22cf462f047318703b92e6f4f38884e4a7ab7b1d6426ca46a8bd1c26cbc',
                'host': 'host.foo.com',
                'Content-Type': 'application/x-www-form-urlencoded',
                'date': 'Mon, 09 Sep 2011 23:36:00 GMT',
            },
            data: 'foo=bar',
        },
    },
    # POST request with querystring (AWS botocore tests).
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/post-vanilla-query.req
    # https://github.com/boto/botocore/blob/879f8440a4e9ace5d3cf145ce8b3d5e5ffb892ef/tests/unit/auth/aws4_testsuite/post-vanilla-query.sreq
    {
        region: 'us-east-1',
        time: '2011-09-09T23:36:00Z',
        credentials: {
            access_key_id: 'AKIDEXAMPLE',
            secret_access_key: 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY',
        },
        original_request: {
            method: 'POST',
            url: 'https://host.foo.com/?foo=bar',
            headers: {'date': 'Mon, 09 Sep 2011 23:36:00 GMT'},
        },
        signed_request: {
            url: 'https://host.foo.com/?foo=bar',
            method: 'POST',
            headers: {
                'Authorization': 'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20110909/us-east-1/host/aws4_request, SignedHeaders=date;host, Signature=b6e3b79003ce0743a491606ba1035a804593b0efb1e20a11cba83f8c25a57a92',
                'host': 'host.foo.com',
                'date': 'Mon, 09 Sep 2011 23:36:00 GMT',
            },
        },
    },
    # GET request with session token credentials.
    {
        region: 'us-east-2',
        time: '2020-08-11T06:55:22Z',
        credentials: {
            access_key_id: ACCESS_KEY_ID,
            secret_access_key: SECRET_ACCESS_KEY,
            security_token: TOKEN,
        },
        original_request: {
            method: 'GET',
            url: 'https://ec2.us-east-2.amazonaws.com?Action=DescribeRegions&Version=2013-10-15',
        },
        signed_request: {
            url: 'https://ec2.us-east-2.amazonaws.com?Action=DescribeRegions&Version=2013-10-15',
            method: 'GET',
            headers: {
                'Authorization': "AWS4-HMAC-SHA256 Credential=#{ACCESS_KEY_ID}/20200811/us-east-2/ec2/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=631ea80cddfaa545fdadb120dc92c9f18166e38a5c47b50fab9fce476e022855",
                'host': 'ec2.us-east-2.amazonaws.com',
                'x-amz-date': '20200811T065522Z',
                'x-amz-security-token': TOKEN,
            },
        },
    },
    # POST request with session token credentials.
    {
        region: 'us-east-2',
        time: '2020-08-11T06:55:22Z',
        credentials: {
            access_key_id: ACCESS_KEY_ID,
            secret_access_key: SECRET_ACCESS_KEY,
            security_token: TOKEN,
        },
        original_request: {
            method: 'POST',
            url: 'https://sts.us-east-2.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15',
        },
        signed_request: {
            url: 'https://sts.us-east-2.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15',
            method: 'POST',
            headers: {
                'Authorization': "AWS4-HMAC-SHA256 Credential=#{ACCESS_KEY_ID}/20200811/us-east-2/sts/aws4_request, SignedHeaders=host;x-amz-date;x-amz-security-token, Signature=73452984e4a880ffdc5c392355733ec3f5ba310d5e0609a89244440cadfe7a7a",
                'host': 'sts.us-east-2.amazonaws.com',
                'x-amz-date': '20200811T065522Z',
                'x-amz-security-token': TOKEN,
            },
        },
    },
    # POST request with computed x-amz-date and no data.
    {
        region: 'us-east-2',
        time: '2020-08-11T06:55:22Z',
        credentials: {'access_key_id': ACCESS_KEY_ID, 'secret_access_key': SECRET_ACCESS_KEY},
        original_request: {
            method: 'POST',
            url: 'https://sts.us-east-2.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15',
        },
        signed_request: {
            url: 'https://sts.us-east-2.amazonaws.com?Action=GetCallerIdentity&Version=2011-06-15',
            method: 'POST',
            headers: {
                'Authorization': "AWS4-HMAC-SHA256 Credential=#{ACCESS_KEY_ID}/20200811/us-east-2/sts/aws4_request, SignedHeaders=host;x-amz-date, Signature=d095ba304919cd0d5570ba8a3787884ee78b860f268ed040ba23831d55536d56",
                'host': 'sts.us-east-2.amazonaws.com',
                'x-amz-date': '20200811T065522Z',
            },
        },
    },
    # POST request with session token and additional headers/data.
    {
        region: 'us-east-2',
        time: '2020-08-11T06:55:22Z',
        credentials: {
            access_key_id: ACCESS_KEY_ID,
            secret_access_key: SECRET_ACCESS_KEY,
            security_token: TOKEN,
        },
        original_request: {
            method: 'POST',
            url: 'https://dynamodb.us-east-2.amazonaws.com/',
            headers: {
                'Content-Type': 'application/x-amz-json-1.0',
                'x-amz-target': 'DynamoDB_20120810.CreateTable',
            },
            data: REQUEST_PARAMS,
        },
        signed_request: {
            url: 'https://dynamodb.us-east-2.amazonaws.com/',
            method: 'POST',
            headers: {
                'Authorization': "AWS4-HMAC-SHA256 Credential=#{ACCESS_KEY_ID}/20200811/us-east-2/dynamodb/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target, Signature=fdaa5b9cc9c86b80fe61eaf504141c0b3523780349120f2bd8145448456e0385",
                'host': 'dynamodb.us-east-2.amazonaws.com',
                'x-amz-date': '20200811T065522Z',
                'Content-Type': 'application/x-amz-json-1.0',
                'x-amz-target': 'DynamoDB_20120810.CreateTable',
                'x-amz-security-token': TOKEN,
            },
            data: REQUEST_PARAMS,
        },
    },
]

  TEST_FIXTURES.each.with_index do |fixture, index|
    it "fulfils Amazon's test \##{index}" do
      allow(Time).to receive(:now).and_return(Time.strptime(fixture[:time], '%Y-%m-%dT%H:%M:%SZ'))
      request_signer = AwsRequestSigner.new(fixture[:region])
      actual_signed_request = request_signer.generate_signed_request(fixture[:credentials], fixture[:original_request])
    end
  end
end
