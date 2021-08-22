package oauth2

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

var randSource = rand.Reader

var b64 = base64.RawURLEncoding

// HS256Token implements a simple abstraction around generating token
// using the hmac-sha256 algorithm.
type HS256Token struct {
	Key       []byte
	Signature []byte
}

// HS256TokenFromKey will return a new hmac-sha256 token that is constructed
// using the specified secret and key.
//
// Note: The secret and the token key should both at least have a length of 16
// characters to be considered unguessable.
func HS256TokenFromKey(secret []byte, key []byte) *HS256Token {
	// create hash
	hash := hmac.New(sha256.New, secret)

	// hash key - implementation does never return an error
	_, _ = hash.Write(key)

	// get signature
	signature := hash.Sum(nil)

	// construct token
	token := &HS256Token{
		Key:       key,
		Signature: signature,
	}

	return token
}

// GenerateHS256Token will return a new hmac-sha256 token that is constructed
// using the specified secret and random key of the specified length.
//
// Note: The secret and the to be generated token key should both at least have
// a length of 16 characters to be considered unguessable.
func GenerateHS256Token(secret []byte, length int) (*HS256Token, error) {
	// prepare key
	key := make([]byte, length)

	// read random bytes
	_, err := io.ReadFull(randSource, key)
	if err != nil {
		return nil, err
	}

	return HS256TokenFromKey(secret, key), nil
}

// MustGenerateHS256Token will generate a token using GenerateHS256Token and
// panic instead of returning an error.
//
// Note: The cryptographically secure pseudo-random number generator provided
// by the operating system may fail. However, such a fail would mean that
// something seriously must be wrong with the machine running this code.
func MustGenerateHS256Token(secret []byte, length int) *HS256Token {
	token, err := GenerateHS256Token(secret, length)
	if err != nil {
		panic(err)
	}

	return token
}

// ParseHS256Token will parse a token that is in its string representation.
func ParseHS256Token(secret []byte, str string) (*HS256Token, error) {
	// split dot separated key and signature
	s := strings.Split(str, ".")
	if len(s) != 2 {
		return nil, errors.New("a token must have two segments separated by a dot")
	}

	// decode key
	key, err := b64.DecodeString(s[0])
	if err != nil {
		return nil, errors.New("token key is not base64 encoded")
	}

	// decode signature
	signature, err := b64.DecodeString(s[1])
	if err != nil {
		return nil, errors.New("token signature is not base64 encoded")
	}

	// construct token
	token := &HS256Token{
		Key:       key,
		Signature: signature,
	}

	// validate signatures
	if !token.Valid(secret) {
		return nil, errors.New("invalid token supplied")
	}

	return token, nil
}

// Valid returns true when the token's key matches its signature.
func (t *HS256Token) Valid(secret []byte) bool {
	return HS256TokenFromKey(secret, t.Key).Equal(t.Signature)
}

// Equal returns true then the specified signature is the same as the token
// signature.
//
// Note: This method should be used over just comparing the byte slices as it
// computed in constant time and limits time based attacks.
func (t *HS256Token) Equal(signature []byte) bool {
	return hmac.Equal(t.Signature, signature)
}

// KeyString returns a string (base64) representation of the key.
func (t *HS256Token) KeyString() string {
	return b64.EncodeToString(t.Key)
}

// SignatureString returns a string (base64) representation of the signature.
func (t *HS256Token) SignatureString() string {
	return b64.EncodeToString(t.Signature)
}

// String returns a string representation of the whole token.
func (t *HS256Token) String() string {
	return t.KeyString() + "." + t.SignatureString()
}
