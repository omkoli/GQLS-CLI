// Command gqls is a production-grade GraphQL security scanner.
package main

import (
	"fmt"
	"os"
)

// Version is the tool version string, overridden at build time via -ldflags.
var Version = "dev"

func main() {
	if err := rootCmd.Execute(); err != nil {
		// failOnThresholdError carries an empty message — the report already
		// explains the situation, so we suppress the blank line but still exit 1.
		if msg := err.Error(); msg != "" {
			fmt.Fprintln(os.Stderr, msg)
		}
		os.Exit(1)
	}
}
