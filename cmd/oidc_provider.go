package cmd

import (
	"log/slog"
	"net/http"

	"github.com/mrtc0-sandbox/go-auth-workload/pkg/helper"
	"github.com/mrtc0-sandbox/go-auth-workload/pkg/provider/oidc/presentation"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(oidcProviderCmd)
}

var oidcProviderCmd = &cobra.Command{
	Use: "oidc-provider",
	Run: func(cmd *cobra.Command, args []string) {
		r := http.NewServeMux()
		r.HandleFunc("/.well-known/jwks", presentation.JwksController)
		r.HandleFunc("/token", presentation.TokenController)

		slog.Info("start listening and serving on :8080")
		err := http.ListenAndServe(":8080", helper.HttpServerLogger(r))
		if err != nil {
			slog.Error("failed to listen and serve", "error", err)
		}
	},
}
