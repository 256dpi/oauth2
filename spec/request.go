package spec

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
)

// A Request is a convenience wrapper to formulate test requests.
type Request struct {
	Method   string
	Path     string
	Header   map[string]string
	Form     map[string]string
	Username string
	Password string
	Callback func(*httptest.ResponseRecorder, *http.Request)
}

// Do will perform the specified request on the specified handler.
func Do(handler http.Handler, req *Request) {
	// create request
	r, err := http.NewRequest(req.Method, req.Path, nil)
	if err != nil {
		panic(err)
	}

	// add headers
	for k, v := range req.Header {
		r.Header.Set(k, v)
	}

	// add basic auth if present
	if req.Username != "" {
		auth := req.Username + ":" + req.Password
		auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
		r.Header.Set("Authorization", auth)
	}

	// prepare form
	r.PostForm = make(url.Values)

	// add params
	for k, v := range req.Form {
		r.PostForm.Set(k, v)
	}

	// prepare recorder
	rec := httptest.NewRecorder()

	// handle request
	handler.ServeHTTP(rec, r)

	// call callback
	req.Callback(rec, r)
}
