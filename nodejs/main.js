/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


const {GoogleAuth, OAuth2Client,IdTokenClient} = require('google-auth-library');

const audience = 'https://example.com';
const url = 'https://httpbin.org/get';

const certs_url='https://www.googleapis.com/oauth2/v1/certs'


async function verifyGoogleIDToken(token, audience, url) {
  const id_client = new IdTokenClient(audience);
  const ticket = await id_client.verifyIdToken({
    idToken: token,
    audience: audience,
  });
  return true;
}

async function verifyIAPIDToken(token, audience) {
  const client = new OAuth2Client();
  const issuer = 'https://cloud.google.com/iap';
  const response = await client.getIapPublicKeys();
  const ticket = await client.verifySignedJwtWithCertsAsync(
   token,
   response.pubkeys,
   audience,
   [issuer]
  );
  const payload = ticket.getPayload();
  console.log('Verified with payload ' + payload);
  return true;
}

async function verifyIDToken(token, issuer, audience, jwkURL) {
  var jwt = require('jsonwebtoken');
  var jwksClient = require('jwks-rsa');
  var client = jwksClient({
    jwksUri: jwkURL
  });
  function getKey(header, callback){
    client.getSigningKey(header.kid, function(err, key) {
      var signingKey = key.publicKey || key.rsaPublicKey;
      callback(null, signingKey);
    });
  }
  var options = {
    algorithm: 'RS256',
    issuer: issuer,
    audience: audience
  }
  jwt.verify(token, getKey, options, function(err, decoded) {
    if (err){
      console.log("Error Verifying "  + err);
      return false
    }
    console.log(decoded)
    return true
  });

  return false;
}

async function main() {
  
 // const auth = new GoogleAuth();
  const auth = new GoogleAuth({
    keyFile: '/path/to/svc.json',
  });

  const client = await auth.getIdTokenClient(
    audience
  );
  const res = await client.request({
    method: 'GET',
    url: url,
  });
  console.log(res.data);

  console.log(client.credentials.id_token);

  let validated = await verifyGoogleIDToken(client.credentials.id_token,audience,certs_url);
  if (validated) {
    console.log("id_token validated with audience " + audience);
  }

  // const iap_id_token = '';
  // const iap_audience = '/projects/248066739582/apps/fabled-ray-104117';
  // let validated = await verifyIAPIDToken(iap_id_token,iap_audience);
  // if (validated) {
  //   console.log("id_token validated with audience " + audience);
  // }

  // const generic_id_token = 'eyJhb...';
  // const generic_endpoint = 'https://raw.githubusercontent.com/istio/istio/release-1.10/security/tools/jwt/samples/jwks.json';
  // const generic_issuer = 'foo.bar';
  // const generic_audience = 'sal';
  // let validated = await verifyIDToken(generic_id_token,generic_issuer, generic_audience,generic_endpoint);
  // if (validated) {
  //   console.log("id_token validated with audience " + audience);
  // }  

}

main().catch(console.error);