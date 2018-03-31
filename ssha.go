package ssha

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
)

/*
NewHash will generate a new SSHA hash with a random salt and return it
*/
func NewHash(in []byte) ([]byte, error) {
	/* Generate a new, cryptographically secure salt */
	salt := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	n, err := rand.Read(salt)
	if n != 16 {
		return nil, fmt.Errorf("Failed to read 16 random bytes for salt")
	}
	if err != nil {
		return nil, fmt.Errorf("Failed to read random bytes for salt: %v", err)
	}

	/* Calculate the SHA-1 Hash */
	sha := sha1.New()
	sha.Write(in)
	sha.Write(salt)

	return sha.Sum(nil), nil
}

/*
NewHashToString will generate a new SSHA hash, with a random salt, and return it as string,
Base64 Encoded, and including the {SSHA} in the beginning
*/
func NewHashToString(in []byte) (string, error) {
	/* Calculate the SSHA hash */
	hash, err := NewHash(in)
	if err != nil {
		return "", err
	}

	/* Prepare the response */
	ret := fmt.Sprintf("{SSHA}%s", base64.StdEncoding.EncodeToString(hash))

	return ret, nil
}
