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


const {JWT} = require('google-auth-library');
const {OAuth2Client} = require('google-auth-library');
const fetch = require("node-fetch");

const audience = 'https://example.com';
const url = 'https://example.com';

const certs_url='https://www.googleapis.com/oauth2/v1/certs'
const metadata_identity_doc_url = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"

async function getIDTokenFromComputeEngine(audience) {
  return fetch(metadata_identity_doc_url + '?audience=' + audience,  { headers: {'Metadata-Flavor': 'Google',} })
  .then(res => res.text())
  .then(body => { return body });
}

async function getIDTokenFromServiceAccount(audience) {
  const keys = require('/path/to/svc.json');
  const opts = {
    "email": keys.client_email,
    "key": keys.private_key,
    "additionalClaims": {"target_audience": audience}
  }
  const client = new JWT(opts);

  const tokenInfo = await client.authorizeAsync();
  
  return tokenInfo.id_token
}

async function verifyIDToken(token, audience, url) {
  const oAuth2Client = new OAuth2Client(audience);
  const ticket = await oAuth2Client.verifyIdToken({
    idToken: token,
    audience: audience,
  });
  return true;
}

async function makeAuthenticatedRequest(idToken, url) {
  return fetch(url,  { headers: {'Authorization': 'Bearer ' + idToken} })
  .then(res => res.text())
  .then(body => { return body });
}

async function main() {
  // If Service Account
  const id_token = await getIDTokenFromServiceAccount(audience);
  
  // If Compute Engine
  //const id_token = await getIDTokenFromComputeEngine(audience);
  
  console.log(id_token);

  let validated = await verifyIDToken(id_token,audience,certs_url);
  if (validated) {
    console.log("id_token validated with audience " + audience);
  }

  console.log(await makeAuthenticatedRequest(id_token, url));
}

main().catch(console.error);