package oauth2

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func newRequest(body map[string]string) *http.Request {
	data := make(url.Values)

	for k, v := range body {
		data.Set(k, v)
	}

	r, err := http.NewRequest("POST", "/foo", strings.NewReader(data.Encode()))
	if err != nil {
		panic(err)
	}

	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return r
}

func newRequestWithAuth(username, password string, body map[string]string) *http.Request {
	r := newRequest(body)
	r.SetBasicAuth(username, password)
	return r
}

func withServer(cb func(string, *Server)) {
	allowedScope := Scope{"foo", "bar"}
	requiredScope := Scope{"foo"}

	serverConfig := DefaultServerConfig([]byte("secret"), allowedScope)

	srv := NewServer(serverConfig)

	handler := http.NewServeMux()
	handler.Handle("/oauth2/", srv)
	handler.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if srv.Authorize(w, r, requiredScope) {
			_, _ = w.Write([]byte("OK"))
		}
	})

	lst, err := net.Listen("tcp", "0.0.0.0:1337")
	if err != nil {
		panic(err)
	}

	s := &http.Server{Handler: handler}
	go s.Serve(lst)

	cb("http://0.0.0.0:1337", srv)

	_ = s.Close()
	_ = lst.Close()

	time.Sleep(time.Millisecond)
}
