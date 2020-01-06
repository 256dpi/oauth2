package client

import (
	"net"
	"net/http"
	"time"

	"github.com/256dpi/oauth2"
	"github.com/256dpi/oauth2/server"
)

func withServer(cb func(string, *server.Server)) {
	allowedScope := oauth2.Scope{"foo", "bar"}
	requiredScope := oauth2.Scope{"foo"}

	serverConfig := server.Default([]byte("secret"), allowedScope)

	srv := server.New(serverConfig)

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
