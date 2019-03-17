package nassh

import (
	"net/http"
)

func ExampleRelay() {
	// Bare minimum server
	r := Relay{}

	m := http.NewServeMux()

	// cookie is the URL the client calls first
	m.HandleFunc("/cookie", func(w http.ResponseWriter, req *http.Request) {
		// this is where you'd handle your authentication flow.

		// Assuming auth is done, this is the last step to continue the SSH
		// process.
		userID := "User from auth flow"
		authSessID := "unique ID to track this login flow"

		ext := req.URL.Query().Get("ext")
		path := req.URL.Query().Get("path")
		version := req.URL.Query().Get("version")
		method := req.URL.Query().Get("method")

		r.StartSession(w, req, userID, authSessID, ext, path, version, method)
	})

	m.HandleFunc("/proxy", r.ProxyHandler)
	m.HandleFunc("/connect", r.ConnectHandler)
}
