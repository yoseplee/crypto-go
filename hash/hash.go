package hash

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
)

func Digest(toHash string, hashMode string) ([]byte, error) {
	switch hashMode {
	case "md5":
		hashed := md5.Sum([]byte(toHash))
		return hashed[:], nil
	case "sha256":
		hashed := sha256.Sum256([]byte(toHash))
		return hashed[:], nil
	case "sha512":
		hashed := sha512.Sum512([]byte(toHash))
		return hashed[:], nil
	default:
		return nil, errors.New("there is no such supported hash mode")
	}
}
