#
# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import google.oauth2.credentials
from google.oauth2 import id_token
from google.oauth2 import service_account
import google.auth
import google.auth.transport.requests
from google.auth.transport.requests import AuthorizedSession
from google.auth import compute_engine 

# pip install google-auth requests

target_audience = 'https://example.com'

url = 'https://cloud-run-url.example.com'
certs_url='https://www.googleapis.com/oauth2/v1/certs'
metadata_identity_doc_url = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"

svcAccountFile = '/path/to/svc_account.json'

def GetIDTokenFromServiceAccount(svcAccountFile, target_audience):
  creds = service_account.IDTokenCredentials.from_service_account_file(
        svcAccountFile,
        target_audience= target_audience)
  request = google.auth.transport.requests.Request()
  creds.refresh(request)
  return creds.token

def GetIDTokenFromComputeEngine(target_audience):
  request = google.auth.transport.requests.Request()
  creds = compute_engine.IDTokenCredentials(request=request, target_audience=target_audience, use_metadata_identity_endpoint=True)
  creds.refresh(request)
  return creds.token

def VerifyIDToken(token, certs_url,  audience=None):
   request = google.auth.transport.requests.Request()
   result = id_token.verify_token(token,request,certs_url=certs_url)
   if audience in result['aud']:
     return True
   return False

def MakeAuthenticatedRequest(id_token, url):
  creds = google.oauth2.credentials.Credentials(id_token)
  authed_session = AuthorizedSession(creds)
  r = authed_session.get(url)
  print r.status_code
  print r.text

# For ServiceAccount
token = GetIDTokenFromServiceAccount(svcAccountFile,target_audience)

# For Compute Engine
#token = GetIDTokenFromComputeEngine(target_audience)

print 'Token: ' + token
if VerifyIDToken(token=token,certs_url=certs_url, audience=target_audience):
  print 'token Verified with aud: ' + target_audience
print 'Making Authenticated API call:'
MakeAuthenticatedRequest(token,url)
