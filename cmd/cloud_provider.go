package cmd

import (
	"log/slog"
	"net/http"

	"github.com/mrtc0-sandbox/go-auth-workload/pkg/helper"
	"github.com/mrtc0-sandbox/go-auth-workload/pkg/provider/cloud/domain/sts"
	cloudPresentation "github.com/mrtc0-sandbox/go-auth-workload/pkg/provider/cloud/presentation"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(cloudProviderCmd)
}

var (
	// Audience. Here, specify sts.cloud.example.com as the Cloud Provider.
	targetAudience = "sts.cloud.example.com"
	// Workload Job Name
	allowedSubject = "acme-workload-system-worker"
	// JWK URL of the OIDC Provider
	acmeWorkloadSystemJwkURL = "http://localhost:8080/.well-known/jwks"
	// Workload Identity Provider ID on the Cloud Provider
	workloadIdentityProviderId = "workload-pool-for-acme-workload-oidc"
)

var cloudProviderCmd = &cobra.Command{
	Use: "cloud-provider",
	Run: func(cmd *cobra.Command, args []string) {
		r := http.NewServeMux()
		r.Handle("/sts", &cloudPresentation.StsTokenController{
			JwksURL:        acmeWorkloadSystemJwkURL,
			TargetAudience: targetAudience,
		})
		r.Handle("/access-token", &cloudPresentation.AccessTokenController{
			Policy: sts.NewAccessControlPolicy(allowedSubject, workloadIdentityProviderId),
		})

		slog.Info("start listening and serving on :9090")
		err := http.ListenAndServe(":9090", helper.HttpServerLogger(r))
		if err != nil {
			slog.Error("failed to listen and serve", "error", err)
		}
	},
}
