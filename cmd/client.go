package cmd

import (
	"log/slog"
	"os"

	"github.com/mrtc0-sandbox/go-auth-workload/pkg/client"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(clientCmd)
}

var clientCmd = &cobra.Command{
	Use: "client",
	Run: func(cmd *cobra.Command, args []string) {
		token, err := client.GetIDToken("sts.cloud.example.com")
		if err != nil {
			slog.Error("failed to get token", "error", err)
			os.Exit(1)
		}

		stsToken, err := client.ExchangeStsToken(token)
		if err != nil {
			slog.Error("failed to exchange sts token", "error", err)
			os.Exit(1)
		}

		slog.Info("successfully get sts token", "token", stsToken)

		accessToken, err := client.GetAccessToken(stsToken)
		if err != nil {
			slog.Error("failed to get access token", "error", err)
			os.Exit(1)
		}

		slog.Info("successfully get access token", "token", accessToken)
	},
}
