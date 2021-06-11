### JWT generation Utility

The following utilities will provide id_tokens for you to test with

#### Self Signed

From istio samples, 


```bash
wget --no-verbose https://raw.githubusercontent.com/istio/istio/release-1.10/security/tools/jwt/samples/gen-jwt.py
wget --no-verbose https://raw.githubusercontent.com/istio/istio/release-1.10/security/tools/jwt/samples/key.pem

python3 gen-jwt.py -iss foo.bar -aud sal -expire 100000 key.pem
```    

which uses `JWK URI = "https://raw.githubusercontent.com/istio/istio/release-1.10/security/tools/jwt/samples/jwks.json"`

and gives a token with claims:

```json
{
  "alg": "RS256",
  "kid": "DHFbpoIUqrY8t2zpA2qXfCmr5VO5ZEr4RzHU_-envvQ",
  "typ": "JWT"
}
.
{
  "aud": "sal",
  "exp": 1623518163,
  "iat": 1623418163,
  "iss": "foo.bar",
  "sub": "foo.bar"
}
```

### Cloud Run Hosted

- [idp-on-cloud-run](https://github.com/yfuruyama/idp-on-cloud-run)


### Firebase/Identity Platform

Its a bit convoluted but to **TEST**, you can acquire a firebase ID token after logging in as a user.
see See [Create OIDC token using Identity Platform](https://github.com/salrashid123/gcpcompat-oidc#create-oidc-token-using-identity-platform)