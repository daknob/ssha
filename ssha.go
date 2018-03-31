package ssha

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"strings"
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

/*
VerifyHash accepts a SSHA string, as well as a plaintext password, and checks whether this
password is correct or not
*/
func VerifyHash(hash, password string) (bool, error) {
	if !IsSSHA(hash) {
		return false, fmt.Errorf("Hash given is not a SSHA hash")
	}

	finalHash, salt, err := GetHashParts(hash)
	if err != nil {
		return false, fmt.Errorf("Failed to parse SSHA hash: %v", err)
	}

	testHash := sha1.New()
	testHash.Write([]byte(password))
	testHash.Write(salt)

	if bytes.Equal(finalHash, testHash.Sum(nil)) {
		return true, nil
	}

	return false, nil
}

/*
IsSSHA checks if a particular string is a SSHA hash or not
*/
func IsSSHA(hash string) bool {
	/* Check if the string begins with {SSHA} */
	if !strings.HasPrefix(hash, "{SSHA}") {
		return false
	}

	/* Check if the string has anything after {SSHA} and it has only one {SSHA} */
	if len(strings.Split(hash, "{SSHA}")) != 2 {
		return false
	}

	/* Get the Base64-Encoded payload of the hash */
	payload := strings.Split(hash, "{SSHA}")[1]

	/* Decode the payload */
	decoded, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return false
	}

	/* Check the payload length */
	if len(decoded) < 21 {
		return false
	}

	return true

}

/*
GetHashParts returns the SSHA hash' Salt and SHA-1 hash
*/
func GetHashParts(hash string) ([]byte, []byte, error) {
	/* Check if hash given is an SSHA hash */
	if !IsSSHA(hash) {
		return nil, nil, fmt.Errorf("Hash given is not an SSHA hash")
	}

	/* Decode the SSHA hash */
	decoded, err := base64.StdEncoding.DecodeString(
		strings.Split(
			hash,
			"{SSHA}",
		)[1],
	)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to decode SSHA hash: %v", err)
	}

	shaone := decoded[0:20]
	salt := decoded[20:]

	return shaone, salt, nil
}

/*
GetSalt returns the SSHA hash salt
*/
func GetSalt(hash string) ([]byte, error) {
	_, salt, err := GetHashParts(hash)
	if err != nil {
		return nil, err
	}

	return salt, nil
}

/*
GetHash returns the SHA-1 hash of an SSHA hash
*/
func GetHash(hash string) ([]byte, error) {
	shaone, _, err := GetHashParts(hash)
	if err != nil {
		return nil, err
	}

	return shaone, nil
}
