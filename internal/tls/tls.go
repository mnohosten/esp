// Package tls provides TLS configuration utilities for ESP.
package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/mnohosten/esp/internal/config"
)

// LoadConfig creates a tls.Config from the given TLS configuration.
// It supports loading certificates from files.
func LoadConfig(cfg config.TLSConfig) (*tls.Config, error) {
	if cfg.CertFile == "" || cfg.KeyFile == "" {
		return nil, nil
	}

	cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: preferredCipherSuites(),
	}

	return tlsConfig, nil
}

// LoadConfigWithClientCA creates a tls.Config that also verifies client certificates.
func LoadConfigWithClientCA(cfg config.TLSConfig, clientCAFile string) (*tls.Config, error) {
	tlsConfig, err := LoadConfig(cfg)
	if err != nil {
		return nil, err
	}
	if tlsConfig == nil {
		return nil, nil
	}

	if clientCAFile != "" {
		caCert, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA file: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse client CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
	}

	return tlsConfig, nil
}

// preferredCipherSuites returns a list of preferred cipher suites for TLS 1.2.
// TLS 1.3 cipher suites are automatically selected and cannot be configured.
func preferredCipherSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}

// NewServerConfig creates a TLS config suitable for servers (SMTP, IMAP, API).
func NewServerConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: preferredCipherSuites(),
	}
}

// NewClientConfig creates a TLS config suitable for outbound connections.
func NewClientConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
}

// NewInsecureClientConfig creates a TLS config that skips certificate verification.
// This should only be used for testing or in trusted environments.
func NewInsecureClientConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
	}
}
