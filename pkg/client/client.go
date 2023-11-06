package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	cloudPresentation "github.com/mrtc0-sandbox/go-auth-workload/pkg/provider/cloud/presentation"
	oidcPresentation "github.com/mrtc0-sandbox/go-auth-workload/pkg/provider/oidc/presentation"
)

func GetIDToken(aud string) (string, error) {
	resp, err := http.Get(fmt.Sprintf("http://localhost:8080/token?aud=%s", aud))
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var response oidcPresentation.TokenResponse
	if err = json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w, %s", err, string(body))
	}

	return response.Token, nil
}

func ExchangeStsToken(token string) (string, error) {
	reqBody, err := json.Marshal(&cloudPresentation.StsTokenRequest{OIDCToken: token})
	if err != nil {
		return "", err
	}

	resp, err := http.Post("http://localhost:9090/sts", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var response cloudPresentation.StsTokenResponse
	if err = json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w, %s", err, string(body))
	}

	return response.Token, nil
}

func GetAccessToken(token string) (string, error) {
	reqBody, err := json.Marshal(&cloudPresentation.AccessTokenRequest{StsToken: token})
	if err != nil {
		return "", err
	}

	resp, err := http.Post("http://localhost:9090/access-token", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var response cloudPresentation.AccessTokenResponse
	if err = json.Unmarshal(body, &response); err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w, %s", err, string(body))
	}

	return response.Token, nil
}
