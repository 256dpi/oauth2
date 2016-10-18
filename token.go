package oauth2

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

var randSource = rand.Reader

var b64 = base64.RawURLEncoding

// Token implements a simple abstraction around generating tokens using the
// hmac-sha256 algorithm.
type Token struct {
	Key       []byte
	Signature []byte
}

// TokenFromKey will return a new token that is constructed using the specified
// secret and key.
//
// Note: The secret and the token key should both at least have a length of 16
// characters to be considered unguessable.
func TokenFromKey(secret []byte, key []byte) *Token {
	// create hash
	hash := hmac.New(sha256.New, secret)

	// hash key - implementation does never return an error
	hash.Write(key)

	// get signature
	signature := hash.Sum(nil)

	// construct token
	token := &Token{
		Key:       key,
		Signature: signature,
	}

	return token
}

// GenerateToken will return a new token that is constructed using the specified
// secret and random key of the specified length.
//
// Note: The secret and the to be generated token key should both at least have
// a length of 16 characters to be considered unguessable.
func GenerateToken(secret []byte, length int) (*Token, error) {
	// prepare key
	key := make([]byte, length)

	// read random bytes
	_, err := io.ReadFull(randSource, key)
	if err != nil {
		return nil, err
	}

	return TokenFromKey(secret, key), nil
}

// ParseToken will parse a token that is in its string representation.
func ParseToken(secret []byte, str string) (*Token, error) {
	// split dot separated key and signature
	s := strings.Split(str, ".")
	if len(s) != 2 {
		return nil, errors.New("A token must have two segments separated by a dot")
	}

	// decode key
	key, err := b64.DecodeString(s[0])
	if err != nil {
		return nil, errors.New("Token key is not base64 encoded")
	}

	// decode signature
	signature, err := b64.DecodeString(s[1])
	if err != nil {
		return nil, errors.New("Token signature is not base64 encoded")
	}

	// construct token
	token := &Token{
		Key:       key,
		Signature: signature,
	}

	// validate signatures
	if !token.Valid(secret) {
		return nil, errors.New("Invalid token supplied")
	}

	return token, nil
}

// Valid returns true when the tokens key matches its signature.
func (t *Token) Valid(secret []byte) bool {
	return TokenFromKey(secret, t.Key).Equal(t.Signature)
}

// Equal returns true then the specified signature is the same as the tokens
// signature.
//
// Note: This method should be used over just comparing the byte slices as it
// computed in constant time and limits certain attacks.
func (t *Token) Equal(signature []byte) bool {
	return hmac.Equal(t.Signature, signature)
}

// KeyString returns a string (base64) representation of the key.
func (t *Token) KeyString() string {
	return b64.EncodeToString(t.Key)
}

// SignatureString returns a string (base64) representation of the signature.
func (t *Token) SignatureString() string {
	return b64.EncodeToString(t.Signature)
}

// String returns a string representation of the whole token.
func (t *Token) String() string {
	return fmt.Sprintf("%s.%s", t.KeyString(), t.SignatureString())
}
