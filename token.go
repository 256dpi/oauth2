package oauth2

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

var randSource = rand.Reader

var b64 = base64.RawURLEncoding

type Token struct {
	Key       []byte
	Signature []byte
}

// Note: The secret and to be generated token should both at least have a length
// of 16 characters to be considered unguessable.
func GenerateToken(secret []byte, length int) (*Token, error) {
	// prepare key
	key := make([]byte, length)

	// read random bytes
	_, err := io.ReadFull(randSource, key)
	if err != nil {
		return nil, err
	}

	// create hash
	hash := hmac.New(sha256.New, secret)

	// hash key - implementation does never return an error
	_, err = hash.Write(key)

	// get signature
	signature := hash.Sum(nil)

	// construct token
	token := &Token{
		Key:       key,
		Signature: signature,
	}

	return token, nil
}

func ParseToken(secret []byte, str string) (*Token, error) {
	// split dot separated key and signature
	s := strings.Split(str, ".")
	if len(s) != 2 {
		return nil, ErrorWithCode(InvalidRequest, "A token must have two segments separated by a dot")
	}

	// decode key
	key, err := b64.DecodeString(s[0])
	if err != nil {
		return nil, ErrorWithCode(InvalidRequest, "Key is not base64 encoded")
	}

	// decode signature
	signature, err := b64.DecodeString(s[1])
	if err != nil {
		return nil, ErrorWithCode(InvalidRequest, "Signature is not base64 encoded")
	}

	// create validation hash
	validationHash := hmac.New(sha256.New, secret)

	// hash key - implementation does never return an error
	_, err = validationHash.Write(key)

	// get signature
	validationSignature := validationHash.Sum(nil)

	// validate signatures
	if !hmac.Equal(signature, validationSignature) {
		return nil, ErrorWithCode(InvalidRequest, "Invalid token by not matching signature")
	}

	// construct token
	token := &Token{
		Key:       key,
		Signature: signature,
	}

	return token, nil
}

func (t *Token) KeyString() string {
	return b64.EncodeToString(t.Key)
}

func (t *Token) SignatureString() string {
	return b64.EncodeToString(t.Signature)
}

func (t *Token) String() string {
	return fmt.Sprintf("%s.%s", t.KeyString(), t.SignatureString())
}
