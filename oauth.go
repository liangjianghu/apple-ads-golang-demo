package main

import (
	"crypto/x509"
	"encoding/pem"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
	"github.com/golang-jwt/jwt/v5"
)

func main() {
	// Define Apple Search Ads credentials and audience URL.
	clientID := "SEARCHADS.APPLEADS-dcff-437a-9513-liangjianghu"
	teamID := "SEARCHADS.APPLEADS-dcff-437a-9513-liangjianghu"
	keyID := "APPLEADS-6536-4d77-ade3-liangjianghu"
	audience := "https://appleid.apple.com"

	// Calculate issuedAt and expiration timestamps.
	issuedAt := time.Now().Unix()
	expiration := issuedAt + 86400*180 // Set token expiration to 180 days from now.

	// Load the private key from a file.
	keyFilePath := "/path/to/your/private-key.pem"
	keyData, err := ioutil.ReadFile(keyFilePath)
	if err != nil {
		panic(err)
	}

	// Decode PEM block containing the private key.
	block, _ := pem.Decode(keyData)
	if block == nil {
		panic("failed to parse PEM block containing the key")
	}

	// Parse the EC private key.
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	// Create JWT token with the specified claims.
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": teamID,
		"iat": issuedAt,
		"exp": expiration,
		"aud": audience,
		"sub": clientID,
	})

	// Set key ID in token header.
	token.Header["kid"] = keyID

	// Sign the token using the private key.
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		panic(err)
	}

	// Save the signed token to a file.
	err = ioutil.WriteFile("client_secret.txt", []byte(signedToken), 0644)
	if err != nil {
		panic(err)
	}

	// Output client secret and its validity period.
	fmt.Println(">> It's recommended to save the clientSecret, with a maximum validity of 180 days.")
	fmt.Println(signedToken)

	// Prepare HTTP request to obtain access token.
	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	formData.Set("client_id", clientID)
	formData.Set("client_secret", signedToken)
	formData.Set("scope", "searchadsorg")
	formData.Set("agency", "ljh")

	req, err := http.NewRequest("POST", "https://appleid.apple.com/auth/oauth2/token", strings.NewReader(formData.Encode()))
	if err != nil {
		panic(err)
	}

	// Set content type for the request.
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// Initialize HTTP client and make the request.
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Decode JSON response into a map.
	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		panic(err)
	}

	// Extract access token from response.
	accessToken, ok := result["access_token"].(string)
	if !ok {
		panic("access_token not found in the response")
	}

	// Output access token and its validity period.
	fmt.Println(">> The access_token is valid for 1 hour.")
	fmt.Println(accessToken)

	// Prepare the HTTP request for accessing the ACLs endpoint
	req, err = http.NewRequest("GET", "https://api.searchads.apple.com/api/v4/acls", nil)
	if err != nil {
		panic(err)
	}

	// Add the Authorization header to the request
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))

	// Initialize HTTP client and make the request
	client = &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	// Read and display the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	fmt.Println(">> Response from ACLs endpoint:")
	fmt.Println(string(body))
}
