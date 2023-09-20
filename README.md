# HTTP Digest Client

This module provides an implementation for communicating with HTTP servers that
utilize digest authentication. It's been structured to allow seamless requests
to endpoints that require this form of authentication.

## Disclaimer

This client is designed based on experience with specific servers and might not
cover all the intricacies of the HTTP digest authentication spec. It has been
tested against a limited set of servers. While it satisfies the needs it was
created for, users should employ caution and conduct tests against their
specific use cases.

## Installation

    npm install node-digest-auth

## Usage

    import {createDigestClient } from 'node-digest-auth'

    // 1 parameter: USERNAME
    // 2 parameter: PASSWORD
    // 3 parameter: SHOULD BE HTTPS
    // 4 parameter: REQUEST SHOULD END OR NOT. IF NOT ENDED YOU CAN WRITE TO THE REQ.

    const digest = createDigestClient('username', 'password', false, true);

    digest.request({
      host: 'hostname.com',
      path: '/path.json',
      port: 80,
      method: 'GET',
      headers: { "User-Agent": "Raphael Fonseca" } // Custom headers can be added as needed
    }, function(res) {
      res.on('data', function(data) {
        console.log(data.toString());
      });
      res.on('error', function(err) {
        console.error('Error occurred:', err);
      });
    });

The client will initially make an unauthenticated request to the server. Once a
challenge is received, the client computes the necessary authentication response
and then repeats the request. If all goes well, the server should then authorize
the request.

## Writing to `req`

set the last parameter of createDigestClient to false, it will return the req
and you can finish it later.

# License

Please refer to the LICENSE file for detailed information on licensing.
