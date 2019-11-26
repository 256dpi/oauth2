package introspection

import (
	"net/http"
	"net/url"
	"strings"
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
