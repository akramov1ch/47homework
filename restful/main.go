package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

type TokenResponse struct {
	Token string `json:"token"`
}

type DataResponse struct {
	Data string `json:"data"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

var tokens = make(map[string]string)

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var u User
	json.NewDecoder(r.Body).Decode(&u)

	if u.Username == "admin" && u.Password == "admin" && u.Role != "" {
		token, err := randomHex(20)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		tokens[token] = u.Role

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{Token: token})
	} else {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
	}
}

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearerToken := r.Header.Get("Authorization")
		if bearerToken == "" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "missing authorization header"})
			return
		}

		splitToken := strings.Split(bearerToken, " ")
		if len(splitToken) != 2 || strings.ToLower(splitToken[0]) != "bearer" {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "invalid authorization header format"})
			return
		}

		reqToken := splitToken[1]
		role, exists := tokens[reqToken]
		if !exists {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "unauthorized"})
			return
		}
		if role != "admin" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Forbidden: Insufficient role"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func resourceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(DataResponse{Data: "resource data"})
}

func main() {
	http.Handle("/resource", authMiddleware(http.HandlerFunc(resourceHandler)))
	http.HandleFunc("/login", loginHandler)

	log.Println("Listening on :9000")
	http.ListenAndServe(":9000", nil)
}

func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}
