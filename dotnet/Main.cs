using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

using Google.Apis.Auth;
using Google.Apis.Http;
using Google.Apis.Auth.OAuth2;
using System.Net.Http;
using System.Net.Http.Headers;
using Google.Apis.Logging;


using Google.Cloud.Iam.Credentials.V1;

namespace Program
{
    public class Program
    {
        [STAThread]
        static void Main(string[] args)
        {
            try
            {                  
                //Google.ApplicationContext.RegisterLogger(new ConsoleLogger(LogLevel.All,true));
                var targetAudience = "https://myapp-6w42z6vi3q-uc.a.run.app";
                string uri = "https://httpbin.org/get";
                string CREDENTIAL_FILE_JSON = "/path/to/svc_accuont.json";
                new Program().Run(targetAudience, CREDENTIAL_FILE_JSON, uri).Wait();
            }
            catch (AggregateException ex)
            {
                foreach (var err in ex.InnerExceptions)
                {
                    Console.WriteLine("ERROR: " + err.Message);
                }
            }

        }


        public async Task<string> Run(string targetAudience, string credentialsFilePath, string uri)
        {
            

            // for ADC on Cloud Run| GCF| GCE
            // both ComputeCredential and GoogleCredentials works and requires "self impersonation"
            // ComputeCredential c = new ComputeCredential();
            // GoogleCredential c = await GoogleCredential.GetApplicationDefaultAsync();
            // OidcToken oidcToken = await c.GetOidcTokenAsync(OidcTokenOptions.FromTargetAudience(targetAudience).WithTokenFormat(OidcTokenFormat.Standard)).ConfigureAwait(false);
            // string token = await oidcToken.GetAccessTokenAsync().ConfigureAwait(false);

            // for ADC local, requires impersonation
            string targetPrincipal = "target-serviceaccount@YOUR_PROJECT.iam.gserviceaccount.com";
            GoogleCredential sourceCredential = await GoogleCredential.GetApplicationDefaultAsync();
            IAMCredentialsClient client = IAMCredentialsClient.Create();
            GenerateIdTokenResponse resp = client.GenerateIdToken(new GenerateIdTokenRequest()
            {
                Name = "projects/-/serviceAccounts/" + targetPrincipal,
                Audience = targetAudience,
                IncludeEmail = true
            });
            string token = resp.Token;

            // // for service accounts
            // ServiceAccountCredential c;
            // using (var fs = new FileStream(credentialsFilePath, FileMode.Open, FileAccess.Read))
            // {
            //     c = ServiceAccountCredential.FromServiceAccountData(fs);
            // }

            //OidcToken oidcToken = await c.GetOidcTokenAsync(OidcTokenOptions.FromTargetAudience(targetAudience).WithTokenFormat(OidcTokenFormat.Standard)).ConfigureAwait(false);            
            //string token = await oidcToken.GetAccessTokenAsync().ConfigureAwait(false);

            // the following snippet verifies an id token. 
            // this step is done on the  receiving end of the oidc endpoint 
            // adding this step in here as just as a demo on how to do this
            //var options = SignedTokenVerificationOptions.Default;
            SignedTokenVerificationOptions options = new SignedTokenVerificationOptions
            {
                IssuedAtClockTolerance = TimeSpan.FromMinutes(1),
                ExpiryClockTolerance = TimeSpan.FromMinutes(1),
                TrustedAudiences = { targetAudience },
                CertificatesUrl = "https://www.googleapis.com/oauth2/v3/certs"  // default value
            };
            var payload = await JsonWebSignature.VerifySignedTokenAsync(token, options);
            Console.WriteLine("Verified with audience " + payload.Audience);
            // end verification

            // use the token
            using (var httpClient = new HttpClient())
            {               
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
                string response = await httpClient.GetStringAsync(uri).ConfigureAwait(false);
                Console.WriteLine(response);
                return response;
            }
        }
    }
}

