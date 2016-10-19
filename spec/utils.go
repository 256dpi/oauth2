package spec

import (
	"fmt"
	"net/http/httptest"
	"net/url"
)

func extend(src, ext map[string]string) map[string]string {
	ret := make(map[string]string)

	// add source keys
	for k, v := range src {
		ret[k] = v
	}

	// add extension keys
	for k, v := range ext {
		ret[k] = v
	}

	return ret
}

func fragment(r *httptest.ResponseRecorder, key string) string {
	// parse location
	u, err := url.Parse(r.HeaderMap.Get("Location"))
	if err != nil {
		panic(err)
	}

	// parse fragment
	f, err := url.ParseQuery(u.Fragment)
	if err != nil {
		panic(err)
	}

	return f.Get(key)
}

func query(r *httptest.ResponseRecorder, key string) string {
	// parse location
	u, err := url.Parse(r.HeaderMap.Get("Location"))
	if err != nil {
		panic(err)
	}

	return u.Query().Get(key)
}

func debug(rec *httptest.ResponseRecorder) interface{} {
	return fmt.Sprintf("\nStatus: %d\nHeader: %v\nBody:   %v", rec.Code, rec.HeaderMap, rec.Body.String())
}
