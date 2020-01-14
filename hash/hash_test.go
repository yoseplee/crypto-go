package hash

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

func TestNew(t *testing.T) {

	hashTestDatas := [3]string{
		"hi there? this is hash test1",
		"hi there? this is hash test2",
		"hi there? this is hash test3",
	}

	//md5
	for _, hashTestData := range hashTestDatas {
		digested, _ := Digest(hashTestData, "md5")
		got := string(digested)
		hashed := md5.Sum([]byte(hashTestData))
		want := string(hashed[:])
		if got != want {
			t.Errorf("incorrect hash value of the two: got = %q, want = %q", got, want)
		}
	}

	//sha256
	for _, hashTestData := range hashTestDatas {
		digested, _ := Digest(hashTestData, "sha256")
		got := string(digested)
		hashed := sha256.Sum256([]byte(hashTestData))
		want := string(hashed[:])
		if got != want {
			t.Errorf("incorrect hash value of the two: got = %q, want = %q", got, want)
		}
	}

	//sha512
	for _, hashTestData := range hashTestDatas {
		digested, _ := Digest(hashTestData, "sha512")
		got := string(digested)
		hashed := sha512.Sum512([]byte(hashTestData))
		want := string(hashed[:])
		if got != want {
			t.Errorf("incorrect hash value of the two: got = %q, want = %q", got, want)
		}
	}
}
