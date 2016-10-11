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

func TestParseScope(t *testing.T) {
	matrix := []struct {
		scp string
		lst []string
		str string
	}{
		{"foo", []string{"foo"}, "foo"},
		{"foo bar", []string{"foo", "bar"}, "foo bar"},
		{" foo  bar  baz ", []string{"foo", "bar", "baz"}, "foo bar baz"},
	}

	for _, i := range matrix {
		scope := ParseScope(i.str)
		assert.Equal(t, i.lst, []string(scope))
		assert.Equal(t, i.str, scope.String())
	}
}

func TestScopeContains(t *testing.T) {
	s := Scope([]string{"foo", "bar"})
	assert.True(t, s.Contains("foo"))
	assert.False(t, s.Contains("baz"))
}

func TestScopeIncludes(t *testing.T) {
	s1 := Scope([]string{"foo", "bar", "baz"})
	s2 := Scope([]string{"foo", "bar"})
	assert.True(t, s1.Includes(s2))
	assert.False(t, s2.Includes(s1))
}
