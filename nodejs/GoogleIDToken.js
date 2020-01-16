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


const {GoogleAuth} = require('google-auth-library');
const {OAuth2Client} = require('google-auth-library');

const audience = 'https://example.com';
const url = 'https://example.com';

const certs_url='https://www.googleapis.com/oauth2/v1/certs'


async function verifyIDToken(token, audience, url) {
  const oAuth2Client = new OAuth2Client(audience);
  const ticket = await oAuth2Client.verifyIdToken({
    idToken: token,
    audience: audience,
  });
  return true;
}

async function main() {

  const auth = new GoogleAuth();
  const client = await auth.getIdTokenClient(
    audience
  );
  const res = await client.request({
    method: 'GET',
    url: url,
  });
  console.log(res.data);

  console.log(client.credentials.id_token);

  let validated = await verifyIDToken(client.credentials.id_token,audience,certs_url);
  if (validated) {
    console.log("id_token validated with audience " + audience);
  }

}

main().catch(console.error);