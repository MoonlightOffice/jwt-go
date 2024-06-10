package jwt

import (
	"encoding/json"
	"testing"
)

func TestJWT(t *testing.T) {
	keyId := "kid-1"
	secret := []byte("asdf")

	type Person struct {
		Name string  `json:"name"`
		Age  float64 `json:"age"`
	}

	// Enocde
	p1 := Person{Name: "John", Age: 24}
	p1Bytes, _ := json.Marshal(p1)

	token, err := Encode(
		JoseHeader{
			Alg:   AlgHS256,
			KeyID: keyId,
		},
		p1Bytes,
		secret,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Check KeyId
	kid, err := ExtractKeyId(token)
	if err != nil {
		t.Fatal(err)
	}
	if keyId != kid {
		t.Fatal("Invalid KeyId:", keyId, kid)
	}

	// Decode
	p2Bytes, err := Decode(token, secret)
	if err != nil {
		t.Fatal(err)
	}

	var p2 Person
	err = json.Unmarshal(p2Bytes, &p2)
	if err != nil {
		t.Fatal(err)
	}

	if !compareStructs(p1, p2) {
		t.Fatal("p1 and p2 don't match")
	}
}
