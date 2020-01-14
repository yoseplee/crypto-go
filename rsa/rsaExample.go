package rsa

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
)

func EncryptDecryptMessage(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, message string) string {

	ciphertext, err := rsa.EncryptPKCS1v15(
		rand.Reader,
		publicKey,
		[]byte(message),
	)

	if err != nil {
		fmt.Println("encrypt error")
		return ""
	}

	plaintext, err := rsa.DecryptPKCS1v15(
		rand.Reader,
		privateKey,
		ciphertext,
	)

	if err != nil {
		fmt.Println("decrypt error")
		return ""
	}

	return string(plaintext)
}

func Digest(message string) []byte {
	digested := md5.Sum([]byte(message))
	return digested[:]
}

func CreateSignature(privateKey *rsa.PrivateKey, message string) []byte {
	digest := Digest(message)
	var h1 crypto.Hash
	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		privateKey,
		h1,
		digest[:],
	)

	if err != nil {
		fmt.Println("error during the creation of signature")
		return nil
	}
	return signature
}

func VerifySignature(publicKey *rsa.PublicKey, signature []byte, message string) bool {
	digest := Digest(message)
	var h1 crypto.Hash
	err := rsa.VerifyPKCS1v15(
		publicKey,
		h1,
		digest[:],
		signature,
	)
	if err != nil {
		return false
	} else {
		return true
	}
}
