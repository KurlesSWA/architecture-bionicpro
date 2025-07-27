package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/cors"
)

type Report struct {
	Data string `json:"data"`
}

type Claims struct {
	RealmAccess struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	PreferredUsername string `json:"preferred_username"`
	jwt.RegisteredClaims
}

var keycloakPublicKey string

func main() {
	err := fetchKeycloakPublicKey()
	if err != nil {
		log.Fatalf("Failed to fetch Keycloak public key: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/reports", reportsHandler)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	})

	handler := c.Handler(mux)

	log.Println("API server starting on port 8080")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

func reportsHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		http.Error(w, "Bearer token required", http.StatusUnauthorized)
		return
	}

	claims, err := validateToken(tokenString)
	if err != nil {
		http.Error(w, fmt.Sprintf("Invalid token: %v", err), http.StatusUnauthorized)
		return
	}

	if !hasProtheticUserRole(claims) {
		http.Error(w, "Forbidden: prothetic_user role required", http.StatusForbidden)
		return
	}

	reportData := fmt.Sprintf("This is a secret report for user: %s", claims.PreferredUsername)
	report := Report{Data: reportData}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

func validateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(keycloakPublicKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}

		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func hasProtheticUserRole(claims *Claims) bool {
	for _, role := range claims.RealmAccess.Roles {
		if role == "prothetic_user" {
			return true
		}
	}
	return false
}

func fetchKeycloakPublicKey() error {
	keycloakURL := os.Getenv("KEYCLOAK_URL")
	realm := os.Getenv("KEYCLOAK_REALM")
	if keycloakURL == "" || realm == "" {
		return fmt.Errorf("KEYCLOAK_URL and KEYCLOAK_REALM environment variables must be set")
	}

	url := fmt.Sprintf("%s/realms/%s", keycloakURL, realm)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to fetch realm info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch realm info: status code %d", resp.StatusCode)
	}

	var realmInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&realmInfo); err != nil {
		return fmt.Errorf("failed to decode realm info: %w", err)
	}

	publicKey, ok := realmInfo["public_key"].(string)
	if !ok {
		return fmt.Errorf("public_key not found in realm info")
	}

	keycloakPublicKey = fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", publicKey)
	return nil
}
