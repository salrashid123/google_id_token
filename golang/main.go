package main

import (
	"context"
	"errors"
	"io/ioutil"
	"log"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat/go-jwx/jwk"
	"google.golang.org/api/idtoken"
)

const ()

var (
	jwtSet *jwk.Set
)

// https://pkg.go.dev/google.golang.org/api@v0.23.0/idtoken

func main() {

	aud := "https://your.endpoint.run.url"
	url := "https://httpbin.org/get"
	jsonCert := "/path/to/svcaccount.json"

	ctx := context.Background()

	// With TokenSource
	// With ADC
	//ts, err := idtoken.NewTokenSource(ctx, aud)
	// With ServiceAccount
	ts, err := idtoken.NewTokenSource(ctx, aud, idtoken.WithCredentialsFile(jsonCert))
	if err != nil {
		log.Fatalf("unable to create TokenSource: %v", err)
	}
	tok, err := ts.Token()
	if err != nil {
		log.Fatalf("unable to retrieve Token: %v", err)
	}

	// the following snippet verifies an id token.
	// this step is done on the  receiving end of the oidc endpoint
	// adding this step in here as just as a demo on how to do this
	// google.golang.org/api/idtoken has built in verification capability for google issued tokens
	log.Printf("IDToken: %s", tok.AccessToken)
	validTok, err := idtoken.Validate(ctx, tok.AccessToken, aud)
	if err != nil {
		log.Fatalf("token validation failed: %v", err)
	}
	if validTok.Audience != aud {
		log.Fatalf("got %q, want %q", validTok.Audience, aud)
	}

	// If you want to verify any other issuer, first get the JWK endpoint,
	// in the following we are validating google's tokens, meaning its equivalent to the bit above
	// this is added in as an example of verifying IAP or other token types
	jwksURL := "https://www.googleapis.com/oauth2/v3/certs"
	jwtSet, err = jwk.FetchHTTP(jwksURL)
	if err != nil {
		log.Fatal("Unable to load JWK Set: ", err)
	}
	doc, err := verifyGoogleIDToken(ctx, tok.AccessToken)

	log.Printf("Verified Token: %v", doc)
	// End verification

	// With Authorized Client
	client, err := idtoken.NewClient(ctx, aud, idtoken.WithCredentialsFile(jsonCert))

	if err != nil {
		log.Fatalf("Could not generate NewClient: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Fatalf("Error Creating HTTP Request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Error making authenticated call: %v", err)
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error Reading response body: %v", err)
	}
	bodyString := string(bodyBytes)
	log.Printf("Authenticated Response: %v", bodyString)

}

// to verify OID token from GCE:

type gcpIdentityDoc struct {
	Google struct {
		ComputeEngine struct {
			InstanceCreationTimestamp int64  `json:"instance_creation_timestamp,omitempty"`
			InstanceID                string `json:"instance_id,omitempty"`
			InstanceName              string `json:"instance_name,omitempty"`
			ProjectID                 string `json:"project_id,omitempty"`
			ProjectNumber             int64  `json:"project_number,omitempty"`
			Zone                      string `json:"zone,omitempty"`
		} `json:"compute_engine"`
	} `json:"google"`
	Email           string `json:"email,omitempty"`
	EmailVerified   bool   `json:"email_verified,omitempty"`
	AuthorizedParty string `json:"azp,omitempty"`
	jwt.StandardClaims
}

func getKey(token *jwt.Token) (interface{}, error) {
	keyID, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("expecting JWT header to have string kid")
	}
	if key := jwtSet.LookupKeyID(keyID); len(key) == 1 {
		log.Printf("     Found OIDC KeyID  " + keyID)
		return key[0].Materialize()
	}
	return nil, errors.New("unable to find key")
}

func verifyGoogleIDToken(ctx context.Context, rawToken string) (gcpIdentityDoc, error) {
	token, err := jwt.ParseWithClaims(rawToken, &gcpIdentityDoc{}, getKey)
	if err != nil {
		log.Printf("     Error parsing JWT %v", err)
		return gcpIdentityDoc{}, err
	}
	if claims, ok := token.Claims.(*gcpIdentityDoc); ok && token.Valid {
		log.Printf("     OIDC doc has Audience [%s]   Issuer [%s] and SubjectEmail [%s]", claims.Audience, claims.StandardClaims.Issuer, claims.Email)
		return *claims, nil
	}
	return gcpIdentityDoc{}, errors.New("Error parsing JWT Claims")
}
