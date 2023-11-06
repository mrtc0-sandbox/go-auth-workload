package jwks

import (
	"context"
	"crypto/rsa"
	"fmt"
	"log/slog"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"

	jwtDomain "github.com/mrtc0-sandbox/go-auth-workload/pkg/provider/oidc/domain/jwt"
)

func VerifyToken(jwksUrl, tokenString string) (*jwtDomain.Token, bool, error) {
	ctx := context.Background()

	set, err := jwk.Fetch(ctx, jwksUrl)
	if err != nil {
		return nil, false, fmt.Errorf("failed to fetch jwks: %w", err)
	}

	for it := set.Keys(ctx); it.Next(ctx); {
		pair := it.Pair()
		key := pair.Value.(jwk.Key)

		var rawKey interface{}
		if err := key.Raw(&rawKey); err != nil {
			slog.Warn("failed to get raw key", "key", key)
		}

		pubkey, ok := rawKey.(*rsa.PublicKey)
		if !ok {
			slog.Warn("failed to cast to rsa.PublicKey", "key", key)
		}

		// derRsaPubkey := x509.MarshalPKCS1PublicKey(pubkey)
		// pem.Encode(os.Stdout, &pem.Block{Type: "RSA PUBLIC KEY", Bytes: derRsaPubkey})

		opt := jws.WithKey(jwa.RS256, pubkey)
		_, err := jws.Verify([]byte(tokenString), opt)
		if err != nil {
			slog.Warn("failed to verify token.", "error", err)
		} else {
			t, err := jwtDomain.NewTokenFromRawTokenString(tokenString)
			if err != nil {
				return nil, false, fmt.Errorf("failed to unmarshal token: %w", err)
			}

			slog.Info("successfully verify token.", "subject", t.Payload.Subject, "audience", t.Payload.Audience)
			return t, true, nil
		}
	}

	return nil, false, fmt.Errorf("cannot find valid keys")
}
