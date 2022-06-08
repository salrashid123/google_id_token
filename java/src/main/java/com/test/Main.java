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
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;

import javax.swing.text.DefaultCaret;

import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.UrlJwkProvider;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken.Payload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.auth.http.HttpCredentialsAdapter;
import com.google.auth.oauth2.ComputeEngineCredentials;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.IdTokenCredentials;
import com.google.auth.oauth2.IdTokenProvider;
import com.google.auth.oauth2.ImpersonatedCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;

public class Main {

     private static final String CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform";
     private static final String credFile = "/path/to/svc.json";
     private static final String target_audience = "https://foo.com";

     public static void main(String[] args) throws Exception {

          Main tc = new Main();

          IdTokenCredentials tok = tc.getIDTokenFromComputeEngine(target_audience);

          // ServiceAccountCredentials sac = ServiceAccountCredentials.fromStream(new FileInputStream(credFile));
          // sac = (ServiceAccountCredentials) sac.createScoped(Arrays.asList(CLOUD_PLATFORM_SCOPE));

          // IdTokenCredentials tok = tc.getIDTokenFromServiceAccount(sac, target_audience);

          // String impersonatedServiceAccount =
          // "impersonated-account@project.iam.gserviceaccount.com";
          // IdTokenCredentials tok =
          // tc.getIDTokenFromImpersonatedCredentials((GoogleCredentials)sac,
          // impersonatedServiceAccount, target_audience);

          System.out.println("Making Authenticated API call:");
          String url = "https://httpbin.org/get";
          tc.MakeAuthenticatedRequest(tok, url);

          // the following snippet verifies an id token.
          // this step is done on the receiving end of the oidc endpoint
          // adding this step in here as just as a demo on how to do this

          System.out.println("Verifying Token:");
          System.out.println(Main.verifyGoogleToken(tok.getAccessToken().getTokenValue(), target_audience));

          // If you want to verify any other issuer, first get the JWK endpoint,
          // in the following we are validating google's tokens, meaning its equivalent to
          // the bit above
          // this is added in as an example of verifying IAP or other token types

          System.out.println("Verifying Token:");
          String jwkUrl = "https://www.googleapis.com/oauth2/v3/certs";
          System.out.println(Main.verifyToken(tok.getAccessToken().getTokenValue(), target_audience, jwkUrl));

     }

     public IdTokenCredentials getIDTokenFromServiceAccount(ServiceAccountCredentials saCreds, String targetAudience) {
          IdTokenCredentials tokenCredential = IdTokenCredentials.newBuilder().setIdTokenProvider(saCreds)
                    .setTargetAudience(targetAudience).build();
          return tokenCredential;
     }

     public IdTokenCredentials getIDTokenFromComputeEngine(String targetAudience) throws IOException {

          // ComputeEngineCredentials caCreds = ComputeEngineCredentials.create();
          // IdTokenCredentials tokenCredential = IdTokenCredentials.newBuilder().setIdTokenProvider(caCreds)
          //           .setTargetAudience(targetAudience)
          //           .setOptions(Arrays.asList(IdTokenProvider.Option.FORMAT_FULL, IdTokenProvider.Option.LICENSES_TRUE))
          //           .build();

          GoogleCredentials caCreds = GoogleCredentials.getApplicationDefault();
          IdTokenCredentials tokenCredential = IdTokenCredentials.newBuilder().setIdTokenProvider((IdTokenProvider)caCreds)
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

     public static boolean verifyGoogleToken(String id_token, String audience) throws Exception {
          GsonFactory jsonFactory = new GsonFactory();
          GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), jsonFactory)
                    .setAudience(Collections.singletonList(audience)).build();
          GoogleIdToken idToken = verifier.verify(id_token);
          if (idToken != null) {
               Payload payload = idToken.getPayload();
               return true;
          } else {
               return false;
          }
     }

     public static boolean verifyToken(String id_token, String audience, String jwkUrl) throws Exception {

          DecodedJWT jwt = JWT.decode(id_token);
          if (jwt.getExpiresAt().before(Calendar.getInstance().getTime())) {
               System.out.println("Expired token");
               return false;
          }
          JwkProvider provider = new UrlJwkProvider(new java.net.URL(jwkUrl));
          Jwk jwk = provider.get(jwt.getKeyId());
          Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
          //Algorithm algorithm = Algorithm.ECDSA256((ECPublicKey) jwk.getPublicKey(),null);

          JWTVerifier verifier = JWT.require(algorithm).withAudience(audience).build();

          try {
               jwt = verifier.verify(id_token);
          } catch (SignatureVerificationException se) {
               System.out.println("Could not verify Signature: " + se.getMessage());
               return false;
          }
          return true;

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
