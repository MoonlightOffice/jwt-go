package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"strings"
)

type JoseHeader struct {
	Alg     string `json:"alg"`
	KeyID   string `json:"kid"`
	KeyType string `json:"typ"`
}

func (header JoseHeader) Encode() string {
	header.KeyType = "JWT"

	b, _ := json.Marshal(header)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (header JoseHeader) GetHashFn() (func() hash.Hash, error) {
	switch header.Alg {
	case AlgHS256:
		return sha256.New, nil
	case AlgHS384:
		return sha512.New384, nil
	case AlgHS512:
		return sha512.New, nil
	default:
		return nil, errors.New("unsupported JWT algorithm")
	}
}

const (
	AlgHS256 string = "HS256"
	AlgHS384 string = "HS384"
	AlgHS512 string = "HS512"
)

func Encode(header JoseHeader, payload []byte, secret []byte) (string, error) {
	eHeader := header.Encode()
	ePayload := base64.RawURLEncoding.EncodeToString(payload)
	msgImprint := fmt.Sprintf("%s.%s", eHeader, ePayload)

	hashFn, err := header.GetHashFn()
	if err != nil {
		return "", err
	}

	mac := hmac.New(hashFn, secret)
	mac.Write([]byte(msgImprint))
	signature := mac.Sum(nil)

	eSignature := base64.RawURLEncoding.EncodeToString(signature)

	jwt := fmt.Sprintf("%s.%s.%s", eHeader, ePayload, eSignature)

	return jwt, nil
}

func Decode(token string, secret []byte) ([]byte, error) {
	header, eJose, ePayload, eSignature, err := extractIntermediates(token)
	if err != nil {
		return nil, err
	}

	hashFn, err := header.GetHashFn()
	if err != nil {
		return nil, err
	}

	// Check signature
	sig1, err := base64.RawURLEncoding.DecodeString(eSignature)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(hashFn, secret)
	msgImprint := fmt.Sprintf("%s.%s", eJose, ePayload)
	mac.Write([]byte(msgImprint))
	sig2 := mac.Sum(nil)
	ok := hmac.Equal(sig1, sig2)
	if !ok {
		return nil, errors.New("invalid signature")
	}

	// Extract payload
	payload, err := base64.RawURLEncoding.DecodeString(ePayload)
	if err != nil {
		return nil, err
	}

	return payload, nil
}

func ExtractKeyId(token string) (string, error) {
	header, _, _, _, err := extractIntermediates(token)
	if err != nil {
		return "", err
	}

	return header.KeyID, nil
}

func extractIntermediates(token string) (header *JoseHeader, eJose, ePayload, eSignature string, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, "", "", "", errors.New("invalid JWS")
	}
	eJose, ePayload, eSignature = parts[0], parts[1], parts[2]

	headerJson, err := base64.RawURLEncoding.DecodeString(eJose)
	if err != nil {
		return nil, "", "", "", err
	}

	err = json.Unmarshal(headerJson, &header)
	if err != nil {
		return nil, "", "", "", err
	}

	if header.KeyType != "JWT" {
		return nil, "", "", "", err
	}

	return header, eJose, ePayload, eSignature, nil
}
