package client

import (
	"io"
	"io/ioutil"
	"net/http"
)

func readAll(res *http.Response, max int) ([]byte, error) {
	// ensure body is closed
	defer res.Body.Close()

	// read full body
	return ioutil.ReadAll(io.LimitReader(res.Body, int64(max)))
}
