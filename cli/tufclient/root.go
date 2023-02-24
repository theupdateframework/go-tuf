package tufclient

import (
	"io"
	"os"

	"github.com/spf13/cobra"
)

var Verbosity bool
var RepositoryURL string

var rootCmd = &cobra.Command{
	Use:   "tuf-client",
	Short: "tuf-client - a client-side CLI tool for The Update Framework (TUF)",
	Long: `tuf-client is a CLI tool that implements the client workflow specified by the The Update Framework (TUF) specification.
   
The tuf-client can be used to query for available targets and to download them in a secure manner.

All downloaded files are verified by signed metadata.`,
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func Execute() {
	rootCmd.PersistentFlags().BoolVarP(&Verbosity, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVarP(&RepositoryURL, "url", "u", "", "URL of the TUF repository")
	rootCmd.MarkFlagRequired("url")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// ReadFile reads the content of a file and return its bytes
func ReadFile(name string) ([]byte, error) {
	in, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	data, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}
	return data, nil
}
