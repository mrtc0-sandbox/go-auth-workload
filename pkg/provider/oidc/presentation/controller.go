package presentation

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/lestrrat-go/jwx/v2/jwk"
	jwkDomain "github.com/mrtc0-sandbox/go-auth-workload/pkg/provider/oidc/domain/jwk"
	jwtDomain "github.com/mrtc0-sandbox/go-auth-workload/pkg/provider/oidc/domain/jwt"
)

const (
	defaultSubject = "acme-workload-system-worker"
)

type TokenResponse struct {
	Token string `json:"token"`
}

func JwksController(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write(makeJwksResponse())
}

func TokenController(w http.ResponseWriter, req *http.Request) {
	aud := req.URL.Query().Get("aud")

	tokenResponse, err := makeTokenResponse(aud)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(tokenResponse)
}

func makeTokenResponse(aud string) ([]byte, error) {
	jwt, err := jwtDomain.NewToken(defaultSubject, aud).Sign()
	if err != nil {
		return nil, fmt.Errorf("failed to make jwt: %w", err)
	}

	resp := &TokenResponse{
		Token: string(jwt),
	}

	r, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal json: %w", err)
	}

	return r, nil
}

func makeJwksResponse() []byte {
	certs, err := os.ReadFile("public-key.pem")
	if err != nil {
		panic(err)
	}

	keyset, err := jwk.ParseKey(certs, jwk.WithPEM(true))
	if err != nil {
		panic(err)
	}

	keyset.Set(jwk.KeyIDKey, jwkDomain.DefaultKid)
	keyset.Set(jwk.AlgorithmKey, jwkDomain.DefaultAlg)
	keyset.Set(jwk.KeyUsageKey, jwkDomain.DefaultUse)

	jwk := map[string]interface{}{
		"keys": []interface{}{keyset},
	}

	buf, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		panic(err)
	}

	return buf
}
