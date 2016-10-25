package spec

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func assert(t *testing.T, ok bool, msg string) {
	if !ok {
		t.Error(msg)
	}
}

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

func jsonField(r *httptest.ResponseRecorder, field string) interface{} {
	srd := strings.NewReader(r.Body.String())
	dec := json.NewDecoder(srd)
	dst := make(map[string]interface{})

	err := dec.Decode(&dst)
	if err != nil {
		panic(err)
	}

	return dst[field]
}

func jsonFieldString(r *httptest.ResponseRecorder, field string) string {
	return jsonField(r, field).(string)
}

func jsonFieldFloat(r *httptest.ResponseRecorder, field string) float64 {
	return jsonField(r, field).(float64)
}

func fragment(r *httptest.ResponseRecorder, key string) string {
	u, err := url.Parse(r.HeaderMap.Get("Location"))
	if err != nil {
		panic(err)
	}

	f, err := url.ParseQuery(u.Fragment)
	if err != nil {
		panic(err)
	}

	return f.Get(key)
}

func query(r *httptest.ResponseRecorder, key string) string {
	u, err := url.Parse(r.HeaderMap.Get("Location"))
	if err != nil {
		panic(err)
	}

	return u.Query().Get(key)
}

func debug(rec *httptest.ResponseRecorder) string {
	return fmt.Sprintf("\nStatus: %d\nHeader: %v\nBody:   %v", rec.Code, rec.HeaderMap, rec.Body.String())
}
