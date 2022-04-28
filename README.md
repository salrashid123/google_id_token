# Authenticating using Google OpenID Connect Tokens


* [What is an id_token?](#what-is-an-id-token)
* [Whats an Audience?](#what-is-an-audience)
* [Sources of Google Issued ID Tokens](#sources-of-google-issued-id-tokens)
* [Making Authorized Requests](#making-authorized-requests)
* [Services Accepting OIDC tokens for authentication](#services-accepting-oidc-tokens-for-authentication)
* [Services that include OIDC tokens in webhooks](#services-that-include-oidc-tokens-in-webhooks)
* [How to get an ID Token?](#how-to-get-an-id-token)
  * [gcloud](#gcloud)
  * [python](#python)
  * [java](#java)
  * [go](#go)
  * [nodejs](#nodejs)
  * [dotnet](#dotnet)
  * [cc](#cc)  
* [How to verify an ID Token?](#how-to-verify-an-id-token)
  * [JWK Endpoints](#jwk-endpoints)
* [References](#references)


This section covers authenticating against security perimeters which requires clients present valid [OpenID Connect tokens](https://openid.net/specs/openid-connect-core-1_0.html#IDToken). These security perimeters do not protect Google APIs but your services deployed behind certain Google Cloud Products. For example, if you deploy to [Cloud Functions](https://cloud.google.com/functions/docs/) or an application on [Cloud Run](https://cloud.google.com/run/docs/), you can enable a perimeter such that any client that wants to invoke the function or your application must present an ID token issued by Google.

These tokens are not Oauth2 [access_tokens](https://developers.google.com/identity/protocols/OAuth2) you would use to call a Google Service or API directly such as a Google Compute Engine API or Cloud Storage Bucket but id_tokens that assert identity and are signed by Google.

## What is an id_token?

OpenIDConnect (OIDC) tokens are signed JSON Web Tokens [JWT](https://tools.ietf.org/html/rfc7519) used to assert identity and do not necessarily carry any implicit authorization against a resource. These tokens will just declare who the caller is and any service that the token is sent to can verify the token's integrity by verifying the signature payload provided with the JWT.  For more information, see the links in the [References](#references) section below

If the ID Token is signed and issued by Google, that token can be used as a token against GCP service perimeters because the service can decode the token, verify its signature and finally identify the caller using values within the JWT claim. For example, the JWT header and payload below describes a token that was issued by google (`"iss": "https://accounts.google.com"`), identifies the caller (`"email": "svc_account@.project.gserviceaccount.com"`), has not expired (the service will check the `exp:` field), and finally will verify the JWT is intended for the service or not to `"aud": "https://example.com"`.


```json
    {
    "alg": "RS256",
    "kid": "5d887f26ce32577c4b5a8a1e1a52e19d301f8181",
    "typ": "JWT"
    }.
    {
    "aud": "https://example.com",
    "azp": "107145139691231222712",
    "email": "svc_account@.project.gserviceaccount.com",
    "email_verified": true,
    "exp": 1556665461,
    "iat": 1556661861,
    "iss": "https://accounts.google.com",
    "sub": "107145139691231222712"
    }
```

>> Note:  the sub claim in the token above represents the unique internal Google identifier account representing the ID Token.

## Whats an Audience?

The `aud:` field describes the service name this token was created to invoke. If a service receives an id_token, it must verify its integrity (signature), validity (is it expired) and if the aud: field is the predefined name it expects to see. If the names do not match, the service should reject the token as it could be a replay intended for another system.

Both Google [Service Accounts](https://cloud.google.com/iam/docs/service-accounts) and Users can get id_tokens but with an important distinction: User login oauth flows issue id_tokens statically bound to the web or oauth2 client_id the flow as associated with. That is, if a user logs into a web application involving oauth2, the id_token that the provider issues to the browser will have the aud: field bound to the oauth2 client_id.

Service Accounts on the other hand, can participate in a flow where it can receive and id_token from google with an aud: field it specified earlier. These token types issued by Service Accounts are generally the ones discussed in this article.

## Sources of Google Issued ID Tokens

There are several ways to get a Google-issued id_token for a Service Account

### Service Account JSON certificate

If you have a Google-issued Service account certificate file locally, you can sign the JWT with specific claims and exchange that with google to get a google-issued id_token. While specifying the claims to sign, a predefined claim called target_audience which when set will be used by Google oauth endpoint and reinterpreted as the aud: field in the id_token.

The flow using a json is:
  *  Use the service account JSON file to sign a JWT with intended final audience set as target_audience.
  *  Exchange the signed JWT with Google token endpoint: `https://oauth2.googleapis.com/token`
  *  Google will verify the signature and identify the aller as the Service Account (since the caller had possession of the private key), then issue an `id_token` with the `aud:` field set to what the `target_audience` was set.
  *  Return the `id_token` in the response back to the client.

### Metadata Server

If a metadata server is available while running on Compute Engine, Appengine 2nd Generation, Cloud Functions or even Kubernetes engine, getting an `id_token` is simple: query the server itself for the token and provide the audience field the token should be for.

For example, the following `curl` command on any platform with metadata server will return an id_token:

```bash
curl -s-H 'Metadata-Flavor: Google' http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=https://example.com`
```

### IAMCredentials generateIdToken()

Google [Cloud IAM Credentials API](https://cloud.google.com/iam/credentials/reference/rest/) provides a way for one service account to generate short lived tokens on behalf of another. One of the token types it can issue is an `id_token` via the [generateIdToken()](https://cloud.google.com/iam/credentials/reference/rest/v1/projects.serviceAccounts/generateIdToken) endpoint.
Making Authorized Requests
Once you have an id_token, provide that in the request Authorization header as:

```
Authorization: Bearer id_token
```

eg.
```bash
curl -v -H "Authorization: Bearer id_token" https://some-cloud-run-uc.a.run.app
```

### Workload Identity Federation

See [Getting GCP IDTokens using Workload Identity Federation](https://github.com/salrashid123/gcp_impersonated_credentials/tree/main/id_token)

## Services Accepting OIDC tokens for authentication

The following platforms use Google OIDC tokens for access controls. If you deploy an application behind any of of these services, you can optionally enable IAM access controls. What that will do is require any inbound access to a service to provide a valid Google OIDC token.

Furthermore, the token must have its aud: field set to the service name being invoked. For example, to invoke a Cloud Run service, you must setup IAM access for the users (see [Managing access via IAM](https://cloud.google.com/run/docs/reference/iam/roles) and any ID token provided must have be signed with the aud: field set to the service name itself. If the Cloud Run service is https://svc.-hash-.zone.cloud.run, the audience field must be set to the same

* [Google Cloud Run](https://cloud.google.com/run/)
* [Google Cloud Functions](https://cloud.google.com/functions/docs/)
* [Google Identity Aware Proxy](https://cloud.google.com/iap/docs/authentication-howto)
* [Google Cloud Endpoints](https://cloud.google.com/endpoints/docs/openapi/authenticating-users-google-id) (if using Google OIDC)

You can also deploy your own service outside of these services and verifying an OpenID Connect token. In this mode, your application that receives an OIDC token will need to manually verify its validity and audience field. You can use application frameworks like to do this like Spring Security, proxies like Envoy or even higher level Services like Istio.

## Services that include OIDC tokens in webhooks

Other services also support automatically including an OIDC token along with a webhook request

* [Cloud Tasks](https://cloud.google.com/tasks/)
* [Cloud Scheduler](https://cloud.google.com/scheduler/)
* [Cloud Pub/Sub](https://cloud.google.com/pubsub/docs/)

For example, you can configure Cloud Scheduler to emit an OIDC token with a preset audience. When a scheduled tasks fires, an http webhook url will be called and within the header payload, the OIDC token will get transmitted within the `Authorization` header. The webhook target can be your own application or any of the services listed in the previous section. If your application is running outside of these services listed under `Services Accepting OIDC tokens` for authentication, you will need to parse and verify the OIDC token.

See:

* [Cloud Scheduler OIDC](https://cloud.google.com/scheduler/docs/http-target-auth#token)
* [Cloud Pub/Sub OIDC](https://cloud.google.com/pubsub/docs/push#using_json_web_tokens_jwts)
* [Cloud Tasks OIDC](https://cloud.google.com/tasks/docs/reference/rpc/google.cloud.tasks.v2beta3#oidctoken)

For detailed implementation, see:
- [Automatic OIDC: Using Cloud Scheduler, Tasks, and PubSub to make authenticated calls to Cloud Run, Cloud Functions or your Server](https://blog.salrashid.dev/articles/2019/automatic_gcp_oidc/)


## How to get an ID Token

There are several flows to get an ID Token available. The snippets below demonstrate how to

1. Get an IDToken
2. Verify an IDToken
3. Issue an authenticated request using the IDToken

Each while using

* Service Account JSON certificate
* Compute Engine Credentials

>> **Disclaimer**: the following snippets potentially use 3rd party libraries and is _not_ supported by Google

### gcloud

- ServiceAccount
```bash
 gcloud auth activate-service-account --key-file=/path/to/svc_account.json
 gcloud auth print-identity-token --audience=https://example.com
```

- ComputeEngine
```
 gcloud auth print-identity-token --audience=https://example.com
```

- ImpersonatedCredentials

```
 gcloud auth print-identity-token --audiences=https://example.com --impersonate-service-account impersonated-account@projectID.iam.gserviceaccount.com
```

### python

- [python/main.py](python/main.py)

### java

- [java/src/main/java/com/test/Main.java](java/src/main/java/com/test/Main.java)

### go

- [golang/main.go](golang/main.go)

### nodejs

- [nodejs/main.js](nodejs/main.js)

### dotnet

- [dotnet/Main.cs](dotnet/Main.cs)

### cc

See [google-cloud-cpp#2786](https://github.com/googleapis/google-cloud-cpp/issues/2786)

- [cc/google_oidc.c](cc/google_oidc.c)


## How to verify an ID Token?

You can verify OIDC tokens manually if the inbound framework you deployed an application to does automatically perform the validation. In these cases, you the snippets provided above describe how to use google and other libraries to download the public certificates used to sign the JWT

* Google Public Certificate URL [https://www.googleapis.com/oauth2/v3/certs](https://www.googleapis.com/oauth2/v3/certs)

Any validation should not just involve verifying the public certificate and validity but also that the audience claim matches the service being invoked.  For more information, see [Validating an ID Token](https://developers.google.com/identity/protocols/OpenIDConnect#validatinganidtoken).  You can find samples [here](https://developers.google.com/identity/sign-in/web/backend-auth#verify-the-integrity-of-the-id-token) that implement validation.

This repo also includes various samples inline that verify tokens preferably by using google auth libraries (where applicable)

It is recommend to always verify locally but for debugging, you can use the [tokenInfo endpoint](https://developers.google.com/identity/sign-in/web/backend-auth#calling-the-tokeninfo-endpoint) or services that decode like jwt.io.


### JWK Endpoints

The following lists out the JWK and OIDC endpoints for google, firebase and IAP

- `Google`
  - `JWK` [https://www.googleapis.com/oauth2/v3/certs](https://www.googleapis.com/oauth2/v3/certs)
  - `x509` [https://www.googleapis.com/oauth2/v2/certs](https://www.googleapis.com/oauth2/v2/certs)
  - [.well-known/openid-configuration](https://accounts.google.com/.well-known/openid-configuration)


- `Firebase/Identity Platform`
  - `JWK` [https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com](https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com)
  - `x509` [https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com](https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com)
  - `.well-known/openid-configuration`  `https://securetoken.google.com/YOUR_PROJECT_ID/.well-known/openid-configuration`  ([eg](https://securetoken.google.com/mineral-minutia-820/.well-known/openid-configuration))
   
- `IAP`
  - `JWK` [https://www.gstatic.com/iap/verify/public_key-jwk](https://www.gstatic.com/iap/verify/public_key-jwk)
  - `x509` [https://www.gstatic.com/iap/verify/public_key](https://www.gstatic.com/iap/verify/public_key)

---

## References

* [ID Tokens Explained](https://www.oauth.com/oauth2-servers/openid-connect/id-tokens/)
* [OpenID Connect id_token](https://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken)
* [OAuth2 access_token](https://developers.google.com/identity/protocols/OAuth2)
* [OpenID Connect on Google APIs](https://developers.google.com/identity/protocols/OpenIDConnect)
