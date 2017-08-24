package main

import (
	"golang.org/x/net/context"
	"encoding/json"
	"log"
	"net/http"
	"golang.org/x/oauth2"
)

var (
	config = oauth2.Config{
		ClientID:     "go",
		ClientSecret: "go",
		Scopes:       []string{"email"},
		RedirectURL:  "http://localhost:9094/oauth2",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://unlimitid.online/oauth/authorize",
			TokenURL: "https://unlimitid.online/oauth/token",
		},
	}
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		u := config.AuthCodeURL("xyz")
		http.Redirect(w, r, u, http.StatusFound)
	})

	http.HandleFunc("/oauth2", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		state := r.Form.Get("state")
		if state != "xyz" {
			http.Error(w, "State invalid", http.StatusBadRequest)
			return
		}
		code := r.Form.Get("code")
		if code == "" {
			http.Error(w, "Code not found", http.StatusBadRequest)
			return
		}
		token, err := config.Exchange(context.Background(), code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		e := json.NewEncoder(w)
		e.SetIndent("", "  ")
		e.Encode(*token)
	})

	log.Println("Client is running at 9094 port.")
	log.Fatal(http.ListenAndServe(":9094", nil))
}
