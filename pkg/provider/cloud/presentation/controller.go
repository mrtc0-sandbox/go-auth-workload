package presentation

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/mrtc0-sandbox/go-auth-workload/pkg/provider/cloud/domain/accesstoken"
	"github.com/mrtc0-sandbox/go-auth-workload/pkg/provider/cloud/domain/jwks"
	"github.com/mrtc0-sandbox/go-auth-workload/pkg/provider/cloud/domain/sts"
)

var (
	// Workload Identity Provider ID on the Cloud Provider
	workloadIdentityProviderId = "workload-pool-for-acme-workload-oidc"
	stsTokenStore              = make(map[string]sts.StsTokenContext)
)

type StsTokenRequest struct {
	OIDCToken string `json:"token"`
}

type AccessTokenRequest struct {
	StsToken string `json:"token"`
}

type StsTokenResponse struct {
	Token string `json:"token"`
}

type AccessTokenResponse struct {
	Token string `json:"token"`
}

type AccessTokenController struct {
	Policy *sts.AccessControlPolicy
}

type StsTokenController struct {
	TargetAudience string
	JwksURL        string
}

func (c *StsTokenController) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	var StsTokenRequest StsTokenRequest

	err := json.NewDecoder(req.Body).Decode(&StsTokenRequest)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed decode: %s", err), http.StatusBadRequest)
		return
	}

	// Verify the OIDC token
	token, isValid, err := jwks.VerifyToken(c.JwksURL, StsTokenRequest.OIDCToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed verify token: %s", err), http.StatusInternalServerError)
		return
	}

	if !isValid {
		slog.Error("invalid token")
		http.Error(w, "invalid token", http.StatusBadRequest)
		return
	}

	if token.Payload.Audience != c.TargetAudience {
		slog.Error("invalid audience")
		http.Error(w, "invalid audience", http.StatusBadRequest)
		return
	}

	// Generate a new STS token
	stsToken := sts.GenerateStsToken()

	// Store the STS token
	stsTokenStore[stsToken] = sts.StsTokenContext{
		Token:       stsToken,
		FederatedBy: workloadIdentityProviderId,
		Payload:     token.Payload,
	}

	// Return the STS token
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&StsTokenResponse{Token: stsToken})
}

func (c *AccessTokenController) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "invalid method", http.StatusBadRequest)
		return
	}

	var accessTokenRequest AccessTokenRequest
	err := json.NewDecoder(req.Body).Decode(&accessTokenRequest)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get the STS token context from the store
	stsTokenContext, ok := stsTokenStore[accessTokenRequest.StsToken]
	if !ok {
		http.Error(w, "sts token not found", http.StatusBadRequest)
		return
	}

	// Verify the STS token
	if ok := c.Policy.IsAuthenticated(&stsTokenContext); !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Generate a new access token
	accessToken := accesstoken.GenerateAccessToken()

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(&AccessTokenResponse{Token: accessToken})
}
