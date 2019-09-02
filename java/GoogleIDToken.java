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

package com.test;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;

import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.ComputeEngineCredentials;
import com.google.auth.oauth2.ImpersonatedCredentials;
import com.google.auth.oauth2.IdTokenCredentials;
import com.google.auth.oauth2.IdTokenProvider;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.auth.oauth2.GoogleCredentials;

public class GoogleIDToken {

     private static final String CLOUD_PLATFORM_SCOPE =  "https://www.googleapis.com/auth/cloud-platform";
     private static final String credFile = "/path/to/svc.json";
     private static final String target_audience = "https://foo.com";

     public static void main(String[] args) throws Exception {

          GoogleIDToken tc = new GoogleIDToken();

          // IdTokenCredentials tok = tc.getIDTokenFromComputeEngine(target_audience);

          ServiceAccountCredentials sac = ServiceAccountCredentials.fromStream(new FileInputStream(credFile));
          sac = (ServiceAccountCredentials)sac.createScoped(Arrays.asList(CLOUD_PLATFORM_SCOPE));

          IdTokenCredentials tok = tc.getIDTokenFromServiceAccount(sac, target_audience);

          //String impersonatedServiceAccount = "impersonated-account@project.iam.gserviceaccount.com";
          //IdTokenCredentials tok = tc.getIDTokenFromImpersonatedCredentials((GoogleCredentials)sac, impersonatedServiceAccount, target_audience);

          System.out.println("Making Authenticated API call:");
          String url = "https://foo.com";
          tc.MakeAuthenticatedRequest(tok, url);

          System.out.println("Verifying Token:");
          System.out.println(TestApp.verifyToken(tok.getAccessToken().getTokenValue(), target_audience));
     }

     public IdTokenCredentials getIDTokenFromServiceAccount(ServiceAccountCredentials saCreds, String targetAudience) {
          IdTokenCredentials tokenCredential = IdTokenCredentials.newBuilder().setIdTokenProvider(saCreds)
                    .setTargetAudience(targetAudience).build();
          return tokenCredential;
     }

     public IdTokenCredentials getIDTokenFromComputeEngine(String targetAudience) {
          ComputeEngineCredentials caCreds = ComputeEngineCredentials.create();
          IdTokenCredentials tokenCredential = IdTokenCredentials.newBuilder().setIdTokenProvider(caCreds)
                    .setTargetAudience(targetAudience)
                    .setOptions(Arrays.asList(IdTokenProvider.Option.FORMAT_FULL, IdTokenProvider.Option.LICENSES_TRUE))
                    .build();
          return tokenCredential;
     }

     public IdTokenCredentials getIDTokenFromImpersonatedCredentials(GoogleCredentials sourceCreds,
               String impersonatedServieAccount, String targetAudience) {
          ImpersonatedCredentials imCreds = ImpersonatedCredentials.create(sourceCreds, impersonatedServieAccount, null,
                    Arrays.asList(CLOUD_PLATFORM_SCOPE), 300);
          IdTokenCredentials tokenCredential = IdTokenCredentials.newBuilder().setIdTokenProvider(imCreds)
                    .setTargetAudience(targetAudience).setOptions(Arrays.asList(IdTokenProvider.Option.INCLUDE_EMAIL))
                    .build();
          return tokenCredential;
     }

     public static boolean verifyToken(String id_token, String audience) throws Exception {
          JacksonFactory jacksonFactory = new JacksonFactory();
          GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), jacksonFactory)
                    .setAudience(Collections.singletonList(audience)).build();
          GoogleIdToken idToken = verifier.verify(id_token);
          if (idToken != null) {
               Payload payload = idToken.getPayload();
               return true;
          } else {
               return false;
          }
     }

     public void MakeAuthenticatedRequest(IdTokenCredentials id_token, String url) throws IOException {

          GenericUrl genericUrl = new GenericUrl(url);
          HttpCredentialsAdapter adapter = new HttpCredentialsAdapter(id_token);
          HttpTransport transport = new NetHttpTransport();
          HttpRequest request = transport.createRequestFactory(adapter).buildGetRequest(genericUrl);
          request.setThrowExceptionOnExecuteError(false);
          HttpResponse response = request.execute();
          String r = response.parseAsString();
          System.out.println(r);

          System.out.println(id_token.getAccessToken().getTokenValue());
          response = request.execute();
          r = response.parseAsString();
          System.out.println(r);
     }
}
