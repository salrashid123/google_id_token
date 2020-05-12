package main

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"

	"google.golang.org/api/idtoken"
)

const ()

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
	log.Printf("IDToken: %s", tok.AccessToken)
	validTok, err := idtoken.Validate(ctx, tok.AccessToken, aud)
	if err != nil {
		log.Fatalf("token validation failed: %v", err)
	}
	if validTok.Audience != aud {
		log.Fatalf("got %q, want %q", validTok.Audience, aud)
	}

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
