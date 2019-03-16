package nassh

import (
	"net/http"

	"github.com/sirupsen/logrus"
)

func ExampleRelay() {
	// Bare minimum server
	r := Relay{
		Logger: logrus.New(),
	}

	m := http.NewServeMux()

	m.HandleFunc("/cookie", r.SimpleCookieHandler)
	m.HandleFunc("/proxy", r.ProxyHandler)
	m.HandleFunc("/connect", r.ConnectHandler)
}
