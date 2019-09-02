
// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

using Google.Apis.Auth.OAuth2;
using Google.Apis.Auth;
using Newtonsoft.Json.Linq;
using System.Net;
using System.Collections.Specialized;
using Microsoft.AspNetCore.WebUtilities;

namespace GoogleIDToken
{

    public class GoogleIDToken
    {
        [STAThread]
        static void Main(string[] args)
        {

          var target_audience = "https://example.com";
          GoogleIDToken  gid = new GoogleIDToken();

          string CREDENTIAL_FILE_JSON = "/path/to/service_account.json";
          ServiceAccountCredential svc_credential;

          using (var stream = new FileStream(CREDENTIAL_FILE_JSON, FileMode.Open, FileAccess.Read))
          {
              svc_credential = ServiceAccountCredential.FromServiceAccountData(stream);
          }

          // For ServiceAccount
          string id_token = gid.GetIDTokenFromServiceAccount(svc_credential, target_audience);
          // For Compute Engine
          //string id_token = gid.GetIDTokenFromComputeEngine(target_audience);

          Console.WriteLine("ID Token: " + id_token);
          gid.VerifyIDToken(id_token).Wait();

          string url = "https://example.com";
          gid.MakeAuthenticatedRequest(id_token,url);
        }

        private string GetIDTokenFromServiceAccount(ServiceAccountCredential svc_credential, string target_audience)
        {
            TimeSpan unix_time = (System.DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0));

            long now = (long)unix_time.TotalSeconds;
            long exp = now + 3600;
            JObject header = new JObject
            {
                ["alg"] = "RS256",
                ["type"] = "JWT"
            };

            JObject claim = new JObject {
                ["iss"] = svc_credential.Id,
                ["aud"] = "https://oauth2.googleapis.com/token",
                ["exp"] =  exp,
                ["iat"] =  now,
                ["target_audience"] = target_audience
            };

            System.Text.UTF8Encoding e = new System.Text.UTF8Encoding();
            String jwt_header_and_claim = WebEncoders.Base64UrlEncode(e.GetBytes(header.ToString())) + "." +  WebEncoders.Base64UrlEncode(e.GetBytes(claim.ToString()));

            var jwt_signature = svc_credential.CreateSignature(System.Text.Encoding.UTF8.GetBytes(jwt_header_and_claim));

            WebClient client = new WebClient();
            NameValueCollection formData = new NameValueCollection();
            formData["grant_type"] = "urn:ietf:params:oauth:grant-type:jwt-bearer";
            formData["assertion"] = jwt_header_and_claim + "." + jwt_signature;;
            client.Headers["Content-type"] = "application/x-www-form-urlencoded";
            try
                {
                    byte[] responseBytes = client.UploadValues("https://oauth2.googleapis.com/token", "POST", formData);
                    string Result = Encoding.UTF8.GetString(responseBytes);

                    var assertion_response = JObject.Parse(Result);
                    var id_token = assertion_response["id_token"];

                    return id_token.ToString();

                } catch (WebException ex)
                {
                    Stream receiveStream = ex.Response.GetResponseStream();
                    Encoding encode = System.Text.Encoding.GetEncoding("utf-8");
                    StreamReader readStream = new StreamReader(receiveStream, encode);
                    string pageContent = readStream.ReadToEnd();
                    Console.WriteLine("Error: " + pageContent);
                    throw new System.Exception("Error while getting IDToken " + ex.Message);
                }
        }

        private async Task VerifyIDToken(string id_token)
        {

          // Verify Token
          var validPayload = await GoogleJsonWebSignature.ValidateAsync(id_token.ToString(),null,true);
          double timestamp = Convert.ToDouble(validPayload.ExpirationTimeSeconds);
          System.DateTime dateTime = new System.DateTime(1970, 1, 1, 0, 0, 0, 0);
          dateTime = dateTime.AddSeconds(timestamp);
          Console.WriteLine("Token Verified; Expires at : " + dateTime);
        }

        private string GetIDTokenFromComputeEngine(string target_audience)
        {

            string metadata_url = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=" + target_audience;
            var client = new WebClient();
            client.Headers.Add("Metadata-Flavor", "Google");
            var id_token = client.DownloadString(metadata_url);
            return id_token;
        }

        private void MakeAuthenticatedRequest(string id_token, string url) {
            var client = new WebClient();
            client.Headers.Add("Authorization", "Bearer " + id_token);
            var result = client.DownloadString(url);
            Console.WriteLine(result);
        }
    }
}
