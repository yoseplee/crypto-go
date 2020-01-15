package rsa

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
)

func TestEncryptDecryptMessage(t *testing.T) {
	privateKey, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
	if err != nil {
		fmt.Println("error during the generating asymmetric key")
	}
	publicKey := &privateKey.PublicKey

	want := "Hi there?"
	if got := EncryptDecryptMessage(privateKey, publicKey, "Hi there?"); got != want {
		t.Errorf("Failed to encrypt and decrypt! want = %q, got = %q", want, got)
	}
}

func TestDigest(t *testing.T) {
	message := "Will you?"
	digested := md5.Sum([]byte(message))
	want := string(digested[:])

	if got := string(Digest(message)[:]); want != got {
		t.Errorf("incorrect digested value...")
	}
}

func TestSignature(t *testing.T) {
	privateKey, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
	if err != nil {
		t.Errorf("failed to generate rsa key pair")
		return
	}
	publicKey := &privateKey.PublicKey

	plaintext := "This is message"

	signature := CreateSignature(privateKey, plaintext)
	isVerifySuccess := VerifySignature(publicKey, signature, plaintext)

	if isVerifySuccess {
		return
	} else {
		t.Errorf("failed to verify signature")
		return
	}
}
