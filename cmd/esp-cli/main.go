// Package main provides the entry point for the ESP CLI tool.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/mnohosten/esp/internal/version"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "esp-cli",
		Short: "ESP CLI - Command line tool for ESP",
		Long:  "Command line tool for managing ESP email server.",
	}

	rootCmd.AddCommand(versionCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("ESP CLI %s\n", version.Version)
			fmt.Printf("Commit: %s\n", version.Commit)
			fmt.Printf("Built: %s\n", version.BuildTime)
		},
	}
}
