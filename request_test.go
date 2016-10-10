package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGrantType(t *testing.T) {
	matrix := []struct {
		gt GrantType
		kn bool
		ex bool
	}{
		{"foo", false, false},
		{"password", true, false},
		{"client_credentials", true, false},
		{"authorization_code", true, false},
		{"refresh_token", true, false},
		{"http://example.com/grants/foo", false, true},
	}

	for _, i := range matrix {
		assert.Equal(t, i.kn, i.gt.Known())
		assert.Equal(t, i.ex, i.gt.Extension())
	}
}
