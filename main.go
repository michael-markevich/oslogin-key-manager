// This package implements a minimalistic SSH key manager for OS Login (Google Cloud Platform)

// Copyright 2025 Michael Markevich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/oslogin/apiv1"
	commonpb "cloud.google.com/go/oslogin/common/commonpb"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	osloginpb "cloud.google.com/go/oslogin/apiv1/osloginpb"
)

// HTTP POST Request structure
// TODO: add expiration time
type HttpPostRequest struct {
	SshKey string `json:"ssh_key"`
}

type HttpDeleteRequest struct {
	KeyId string `json:"key_id"`
}

// JWT claims structure
type Claims struct {
	Email string `json:"email"`
	Token string `json:"token"`
	Photo string `json:"photo"`
	Name  string `json:"name"`
	jwt.RegisteredClaims
}

type IndexTemplate struct {
    Name  string
    Email string
    Photo string
}

//go:embed templates
var templates embed.FS
var templatesPtr *template.Template

// Global encryption key for secrets
var encryptionKey []byte
var jwtSecret []byte

// OAuth2 configuration
var oauthConfig *oauth2.Config

var listenHost string
var listenPort string

// Generate a random 32-byte encryption key
func generateKey() ([]byte, error) {
	key := make([]byte, 32) // 32 bytes for AES-256
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// Encrypt data using AES-GCM
func encrypt(plainText string) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	cipherText := aesGCM.Seal(nonce, nonce, []byte(plainText), nil)
	return base64.StdEncoding.EncodeToString(cipherText), nil
}

// Decrypt data
func decrypt(encryptedText string) (string, error) {
	cipherText, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	nonce, cipherText := cipherText[:nonceSize], cipherText[nonceSize:]

	plainText, err := aesGCM.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(plainText), nil
}

// Generate a JWT token
func generateJWT(email, token, photo, name string) (string, error) {
	// Define expiration time (e.g., 1 hour)
	expirationTime := time.Now().Add(time.Hour)

	// Create claims with email, token, and other information from a user profile
	claims := &Claims{
		Email: email,
		Token: token,
		Photo: photo,
		Name:  name,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	// Create the token with claims
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign the token
	signedToken, err := newToken.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// Validate and parse JWT from cookie
func validateJWT(tokenString string) (*Claims, error) {
	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}

	// Extract and return claims
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, fmt.Errorf("invalid token")
}

// rootHandler displays the home page
func rootHandler(w http.ResponseWriter, r *http.Request) {

	// Retrieve the access token from the cookie
	cookie, err := r.Cookie("session_token")
	if err != nil {
		w.Header().Set("Content-Type", "text/html")
		renderedIndex := templatesPtr.ExecuteTemplate(w, "login.html", nil)
		if renderedIndex != nil { /* handle error */ 
			http.Error(w, "Unable to render template", http.StatusBadRequest)
		}
		return
	}

	// Validate JWT
	claims, err := validateJWT(cookie.Value)
	if err != nil {
		http.Redirect(w, r, "/auth/logout", http.StatusFound)
		return
	}

    pageData := IndexTemplate{
        Name: claims.Name,
        Email: claims.Email,
        Photo: claims.Photo,
    }

	w.Header().Set("Content-Type", "text/html")
	renderedIndex := templatesPtr.ExecuteTemplate(w, "index.html", pageData)
	if renderedIndex != nil { /* handle error */ 
		http.Error(w, "Unable to render template", http.StatusBadRequest)
	}
}

// loginHandler redirects the user to Google's OAuth2 consent page
func loginHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	// TODO: random-state
	authURL := oauthConfig.AuthCodeURL("random-state", oauth2.AccessTypeOffline)
	http.Redirect(w, r.WithContext(ctx), authURL, http.StatusFound)
}

// logoutHandler ends the user session
func logoutHandler(w http.ResponseWriter, r *http.Request) {

	// Expire the cookie to log the user out
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Expires:  time.Now().Add(-time.Hour), // Set expiration in the past
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // TODO: true
	})

	// Redirect to the home page
	http.Redirect(w, r, "/", http.StatusFound)
}

// callbackHandler processes the OAuth2 callback from Google
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// TODO: check for state

	// Retrieve the authorization code from the request
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	// Exchange the code for an access token
	token, err := oauthConfig.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Fetch user info using the access token
	userInfo, err := getUserInfo(ctx, token)
	if err != nil {
		http.Error(w, "Failed to get user info: "+err.Error(), http.StatusInternalServerError)
		return
	}

	email, ok := userInfo["email"].(string)
	if !ok {
		log.Printf("Field 'email' is not a valid string")
		return
	}

	photo, ok := userInfo["picture"].(string)
	if !ok {
		log.Printf("Field 'picture' is not a valid string for %s", email)
	}

	name, ok := userInfo["name"].(string)
	if !ok {
		log.Printf("Field 'name' is not a valid string for %s", email)
	}

	// Encrypt the access token
	encryptedToken, err := encrypt(token.AccessToken)

	// Generate JWT
	jwToken, err := generateJWT(email, encryptedToken, photo, name)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Store the access token in a cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    jwToken,
		Expires:  token.Expiry,
		Path:     "/",
		HttpOnly: true,  // Prevent JavaScript access
		Secure:   false, // TODO: true
	})

	// Send a login event to logger
	log.Printf("User %s has logged in!", email)

	// Redirect back to the home page
	http.Redirect(w, r, "/", http.StatusFound)
}

// keysHandler processes key management requests
func keysHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Retrieve the access token from the cookie
	cookie, err := r.Cookie("session_token")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Validate JWT
	claims, err := validateJWT(cookie.Value)
	if err != nil {
		http.Error(w, "Invalid session token", http.StatusUnauthorized)
		return
	}

	ct := r.Header.Get("Content-Type")
	if ct != "" {
		mediaType := strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
		if mediaType != "application/json" {
			msg := "Content-Type header is not application/json"
			http.Error(w, msg, http.StatusUnsupportedMediaType)
			return
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1048576)

	// Decrypt and prepare the access token
	decryptedToken, err := decrypt(claims.Token)
	token := &oauth2.Token{AccessToken: decryptedToken}
	tokenSource := oauth2.StaticTokenSource(token)

	client, err := oslogin.NewClient(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		log.Println("Unable to create OS Login client: %v", err)
		return
	}
	defer client.Close()

	// Fetch a username from JWT
	myUser := fmt.Sprintf("users/%s", claims.Email)

	switch r.Method {
	case "GET":

		// Create the request to get the login profile
		req := &osloginpb.GetLoginProfileRequest{
			Name: myUser,
		}

		// Fetch the user profile from OS Login API
		resp, err := client.GetLoginProfile(ctx, req)
		if err != nil {
			log.Printf("Failed to get OS login profile: %v", err)
		}

		// Return the retrieved user login profile
		json.NewEncoder(w).Encode(resp)

	case "POST":
		// Configure JSON decoder
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		// Parse JSON request
		var reqHttp HttpPostRequest
		err = decoder.Decode(&reqHttp)
		if err != nil {
			http.Error(w, "Unable to parse JSON", http.StatusBadRequest)
			return
		}

		// Check that the JSON body has only one element
		err = decoder.Decode(&struct{}{})
		if !errors.Is(err, io.EOF) {
			http.Error(w, "Request body must only contain a single JSON object", http.StatusBadRequest)
			return
		}

		// Create the request to upload the SSH public key
		newKey := &commonpb.SshPublicKey{Key: reqHttp.SshKey}
		req := &osloginpb.CreateSshPublicKeyRequest{
			Parent:       myUser, // The user identifier in the format "users/{email}"
			SshPublicKey: newKey, // The SSH public key
		}

		// Upload the SSH public key for the user
		resp, err := client.CreateSshPublicKey(ctx, req)
		if err != nil {
			log.Printf("Failed to upload SSH key: %v", err)
			return
		}

		// Print the response from the API (optional)
		log.Printf("SSH key uploaded: %v\n", resp.Name)

	case "DELETE":
		// Configure JSON decoder
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		// Parse JSON request
		var reqHttp HttpDeleteRequest
		err = decoder.Decode(&reqHttp)
		if err != nil {
			http.Error(w, "Unable to parse JSON", http.StatusBadRequest)
			return
		}

		// Check that the JSON body has only one element
		err = decoder.Decode(&struct{}{})
		if !errors.Is(err, io.EOF) {
			http.Error(w, "Request body must only contain a single JSON object", http.StatusBadRequest)
			return
		}

		// Delete the uploaded SSH key using its fingerprint
		keyName := fmt.Sprintf("%s/sshPublicKeys/%s", myUser, reqHttp.KeyId)
		deleteReq := &osloginpb.DeleteSshPublicKeyRequest{
			Name: keyName,
		}

		// Delete the SSH public key for the user
		if err := client.DeleteSshPublicKey(ctx, deleteReq); err != nil {
			log.Printf("Failed to delete SSH key: %v", err)
		}

		// Print success message
		log.Printf("SSH key deleted: %v\n", keyName)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}

}

// getUserInfo retrieves the authenticated user's profile information from Google
func getUserInfo(ctx context.Context, token *oauth2.Token) (map[string]interface{}, error) {
	client := oauthConfig.Client(ctx, token)

	// Make a request to Google's userinfo API
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Parse the response JSON
	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, err
	}

	return userInfo, nil
}

// The standard initialization function
func init() {
	var init_err error

	// Load HTML templates
	templatesPtr, init_err = template.ParseFS(templates, "templates/*.html")
	if init_err != nil {
		log.Fatalf("Unable to parse templates: %s", init_err)
	}

	// Generate a random encryption key (TODO: use a file/variable for persistence)
	encryptionKey, init_err = generateKey()
	if init_err != nil {
		log.Fatalf("Error generating an encryption key: %s", init_err)
	}

	// Generate a random JWT secret (TODO: use a file/variable for persistence)
	jwtSecret, init_err = generateKey()
	if init_err != nil {
		log.Fatalf("Error generating a JWT secret: %s", init_err)
	}

	// Read environment variables
	clientID := os.Getenv("GOOGLE_CLIENT_ID")
	if clientID == "" {
		log.Fatalf("Environment variable GOOGLE_CLIENT_ID is not set!")
	}

	clientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	if clientSecret == "" {
		log.Fatalf("Environment variable GOOGLE_CLIENT_SECRET is not set!")
	}

	redirectURL := os.Getenv("OAUTH2_REDIRECT_URL")
	if redirectURL == "" {
		log.Fatalf("Environment variable OAUTH2_REDIRECT_URL is not set!")
	}

	// If the LISTEN_HOST variable doesn't exist, we listen to all ports
	listenHost = os.Getenv("LISTEN_HOST")
	listenPort = os.Getenv("LISTEN_PORT")
	if listenPort == "" {
		listenPort = "8080"
	}

	oauthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"https://www.googleapis.com/auth/cloud-platform", "email", "profile", "openid"},
		Endpoint:     google.Endpoint,
	}
}

func main() {
	// Register HTTP handlers
	http.HandleFunc("/", rootHandler)
	http.HandleFunc("/auth/callback", callbackHandler)
	http.HandleFunc("/auth/login", loginHandler)
	http.HandleFunc("/auth/logout", logoutHandler)
	http.HandleFunc("/keys", keysHandler)

	// Configure the HTTP server
	listenAddress := fmt.Sprintf("%s:%s", listenHost, listenPort)
	server := &http.Server{
		Addr:              listenAddress,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Start the HTTP server
	log.Printf("Starting application server on '%s'\n", listenAddress)
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
