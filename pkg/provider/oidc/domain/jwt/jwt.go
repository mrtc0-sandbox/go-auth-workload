package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	DefaultAudience = "acme-workload-system-worker"
	DefaultIssuer   = "http://localhost:8080"
)

type Payload struct {
	Issuer   string `json:"iss"`
	Subject  string `json:"sub"`
	Audience string `json:"aud"`
	IssuedAt int64  `json:"iat"`
	Expires  int64  `json:"exp"`
}

type Header struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type Token struct {
	Header  Header  `json:"header"`
	Payload Payload `json:"payload"`
}

func NewToken(subject, audience string) *Token {
	if audience == "" {
		audience = DefaultAudience
	}

	return &Token{
		Header: Header{
			Alg: "RS256",
			Kid: "123456789",
			Typ: "JWT",
		},
		Payload: Payload{
			Issuer:   DefaultIssuer,
			Subject:  subject,
			Audience: audience,
			IssuedAt: time.Now().Unix(),
			Expires:  time.Now().Add(time.Minute * 5).Unix(),
		},
	}
}

func (t *Token) Sign() (string, error) {
	header, err := t.Header.encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %w", err)
	}

	payload, err := t.Payload.encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode payload: %w", err)
	}

	headerAndPayload := fmt.Sprintf("%s.%s", header, payload)

	privateKey, err := readPrivateKey()
	if err != nil {
		return "", err
	}

	hasher := sha256.New()
	hasher.Write([]byte(headerAndPayload))
	tokenHash := hasher.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, tokenHash)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	enc := base64.RawURLEncoding.EncodeToString(signature)
	return fmt.Sprintf("%s.%s", headerAndPayload, enc), nil
}

func (h *Header) encode() (string, error) {
	j, err := json.Marshal(h)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(j), nil
}

func (p *Payload) encode() (string, error) {
	j, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(j), nil
}

func readPrivateKey() (*rsa.PrivateKey, error) {
	data, err := os.ReadFile("private-key.pem")
	if err != nil {
		return nil, err
	}

	keyblock, _ := pem.Decode(data)

	if keyblock == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	if keyblock.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("invalid private key type : %s", keyblock.Type)
	}

	keyInterface, err := x509.ParsePKCS8PrivateKey(keyblock.Bytes)
	if err != nil {
		return nil, err
	}

	var ok bool
	privateKey, ok := keyInterface.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not RSA private key")
	}

	err = privateKey.Validate()
	if err != nil {
		return nil, fmt.Errorf("private key is invalid: %w", err)
	}

	return privateKey, nil
}

func NewTokenFromRawTokenString(token string) (*Token, error) {
	parts := strings.Split(token, ".")
	var t Token

	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	var tokenHeader Header
	err = json.Unmarshal(header, &tokenHeader)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	var tokenPayload Payload
	err = json.Unmarshal(payload, &tokenPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	t.Header = tokenHeader
	t.Payload = tokenPayload

	return &t, nil
}
