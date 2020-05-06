package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
	s := Scope{"foo", "bar"}
	assert.True(t, s.Contains("foo"))
	assert.False(t, s.Contains("baz"))
}

func TestScopeIncludes(t *testing.T) {
	s0 := Scope{}
	assert.True(t, s0.Includes(s0))

	s1 := Scope{"foo", "bar", "baz"}
	s2 := Scope{"foo", "bar"}
	assert.True(t, s1.Includes(s2))
	assert.False(t, s2.Includes(s1))
}

func TestScopeEmpty(t *testing.T) {
	s0 := Scope{}
	assert.True(t, s0.Empty())

	s1 := Scope{"foo"}
	assert.False(t, s1.Empty())
}

func TestScopeMarshalJSON(t *testing.T) {
	s := Scope{"foo", "bar"}
	buf, _ := s.MarshalJSON()
	assert.Equal(t, `"foo bar"`, string(buf))
}
