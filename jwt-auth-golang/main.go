package main

import (
	"fmt"
	"net/http"

	"github.com/cheildo/jwt-auth-golang/login"
	"github.com/gorilla/mux"
)

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Missing authorization header")
			return
		}
		tokenString = tokenString[len("Bearer "):]

		claims, err := login.VerifyToken(tokenString)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "Invalid token")
			return
		}
		if claims["role"] != "admin" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Forbidden: Insufficient role")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	router := mux.NewRouter()

	router.HandleFunc("/login", login.LoginHandler).Methods("POST")
	router.Handle("/protected", authMiddleware(http.HandlerFunc(login.ProtectedHandler))).Methods("GET")

	fmt.Println("Starting the server")
	err := http.ListenAndServe("localhost:4000", router)
	if err != nil {
		fmt.Println("Could not start the server", err)
	}

	fmt.Println("Server started. Listening on port 4000")
}
