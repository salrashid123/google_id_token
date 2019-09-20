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
package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"time"

	"golang.org/x/net/context"

	"golang.org/x/oauth2/google"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2/jws"
)

const (
	googleRootCertURL      = "https://www.googleapis.com/oauth2/v3/certs"
	audience               = "https://example.com"
	jsonCert               = "/path/to/service_account.json"
	metadataIdentityDocURL = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity"
)

func getIDTokenFromServiceAccount(ctx context.Context, audience string) (string, error) {
	data, err := ioutil.ReadFile(jsonCert)
	if err != nil {
		return "", err
	}

	conf, err := google.JWTConfigFromJSON(data, "")
	if err != nil {
		return "", err
	}

	header := &jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
		KeyID:     conf.PrivateKeyID,
	}

	privateClaims := map[string]interface{}{"target_audience": audience}
	iat := time.Now()
	exp := iat.Add(time.Hour)

	payload := &jws.ClaimSet{
		Iss:           conf.Email,
		Iat:           iat.Unix(),
		Exp:           exp.Unix(),
		Aud:           "https://www.googleapis.com/oauth2/v4/token",
		PrivateClaims: privateClaims,
	}

	key := conf.PrivateKey
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(key)
		if err != nil {
			return "", err
		}
	}
	parsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		log.Fatal("private key is invalid")
	}

	token, err := jws.Encode(header, payload, parsed)
	if err != nil {
		return "", err
	}

	d := url.Values{}
	d.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	d.Add("assertion", token)

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://www.googleapis.com/oauth2/v4/token", strings.NewReader(d.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var y map[string]interface{}
	err = json.Unmarshal([]byte(body), &y)
	if err != nil {
		return "", err
	}
	return y["id_token"].(string), nil
}

func getIDTokenFromComputeEngine(ctx context.Context, audience string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("GET", metadataIdentityDocURL+"?audience="+audience, nil)
	req.Header.Add("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	bodyString := string(bodyBytes)
	return bodyString, nil
}

func verifyGoogleIDToken(ctx context.Context, aud string, token string) (bool, error) {

	keySet := oidc.NewRemoteKeySet(ctx, googleRootCertURL)

	// https://github.com/coreos/go-oidc/blob/master/verify.go#L36
	var config = &oidc.Config{
		SkipClientIDCheck: false,
		ClientID:          aud,
	}
	verifier := oidc.NewVerifier("https://accounts.google.com", keySet, config)

	idt, err := verifier.Verify(ctx, token)
	if err != nil {
		return false, err
	}
	log.Printf("Verified id_token with Issuer %v: ", idt.Issuer)
	return true, nil
}

func makeAuthenticatedRequest(idToken string, url string) {

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", "Bearer "+idToken)
	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	bodyString := string(bodyBytes)
	log.Printf("Authenticated Response: %v", bodyString)
}

func main() {

	ctx := context.Background()

	// For Service Account
	idToken, err := getIDTokenFromServiceAccount(ctx, audience)

	// For Compute Engine
	//idToken, err := getIDTokenFromComputeEngine(ctx,audience)

	if err != nil {
		log.Fatalf("%v", err)
	}

	log.Printf("IDToken: %v", idToken)
	verified, err := verifyGoogleIDToken(ctx, audience, idToken)
	if err != nil {
		log.Fatalf("%v", err)
	}
	log.Printf("Verify %v", verified)

	u := "https://example.com"
	makeAuthenticatedRequest(idToken, u)
}
