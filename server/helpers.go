package server

import "golang.org/x/crypto/bcrypt"

// MustHash will hash the specified clear text using bcrypt.
func MustHash(clear string) []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte(clear), bcrypt.MinCost)
	if err != nil {
		panic(err)
	}

	return hash
}

// SameHash verifies if the provided clear text and bcrypt hash are equal.
func SameHash(hash []byte, clear string) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(clear)) == nil
}
