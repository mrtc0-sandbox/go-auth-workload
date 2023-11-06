package sts

import (
	"crypto/rand"
	"fmt"

	jwtDomain "github.com/mrtc0-sandbox/go-auth-workload/pkg/provider/oidc/domain/jwt"
)

type StsTokenContext struct {
	Token       string
	FederatedBy string
	Payload     jwtDomain.Payload
}

func GenerateStsToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("sts_%x", b)
}
