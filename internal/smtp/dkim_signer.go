package smtp

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/emersion/go-msgauth/dkim"
	"github.com/mnohosten/esp/internal/config"
)

// DKIMSigner handles DKIM signing of outgoing messages.
type DKIMSigner struct {
	config config.DKIMConfig
	logger *slog.Logger

	// Cache loaded keys
	keyCache   map[string]*rsa.PrivateKey
	keyCacheMu sync.RWMutex
}

// NewDKIMSigner creates a new DKIM signer.
func NewDKIMSigner(cfg config.DKIMConfig, logger *slog.Logger) *DKIMSigner {
	return &DKIMSigner{
		config:   cfg,
		logger:   logger.With("component", "smtp.dkim"),
		keyCache: make(map[string]*rsa.PrivateKey),
	}
}

// Sign signs a message with DKIM.
// Returns the signed message content, or the original content if signing fails.
func (s *DKIMSigner) Sign(content []byte, domain string) ([]byte, error) {
	if !s.config.Enabled {
		return content, nil
	}

	// Load private key for domain
	key, err := s.loadKey(domain)
	if err != nil {
		s.logger.Warn("failed to load DKIM key, sending unsigned",
			"domain", domain,
			"error", err,
		)
		return content, nil // Return unsigned message
	}

	// Create DKIM sign options
	opts := &dkim.SignOptions{
		Domain:   domain,
		Selector: s.config.Selector,
		Signer:   key,
		Hash:     crypto.SHA256,
		HeaderKeys: []string{
			"From",
			"To",
			"Subject",
			"Date",
			"Message-ID",
			"MIME-Version",
			"Content-Type",
			"Content-Transfer-Encoding",
		},
	}

	// Sign the message
	var signedBuf bytes.Buffer
	if err := dkim.Sign(&signedBuf, bytes.NewReader(content), opts); err != nil {
		s.logger.Error("failed to sign message",
			"domain", domain,
			"error", err,
		)
		return content, fmt.Errorf("DKIM signing failed: %w", err)
	}

	s.logger.Debug("message signed with DKIM",
		"domain", domain,
		"selector", s.config.Selector,
	)

	return signedBuf.Bytes(), nil
}

// loadKey loads the private key for a domain from disk.
func (s *DKIMSigner) loadKey(domain string) (*rsa.PrivateKey, error) {
	// Check cache first
	s.keyCacheMu.RLock()
	if key, ok := s.keyCache[domain]; ok {
		s.keyCacheMu.RUnlock()
		return key, nil
	}
	s.keyCacheMu.RUnlock()

	// Build key path
	keyPath := s.config.KeyPath
	keyPath = strings.ReplaceAll(keyPath, "$domain", domain)
	keyPath = strings.ReplaceAll(keyPath, "$selector", s.config.Selector)

	// Read key file
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file %s: %w", keyPath, err)
	}

	// Parse PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block from %s", keyPath)
	}

	// Parse private key
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
		}
	case "PRIVATE KEY":
		parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
		}
		var ok bool
		key, ok = parsedKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}

	// Cache the key
	s.keyCacheMu.Lock()
	s.keyCache[domain] = key
	s.keyCacheMu.Unlock()

	s.logger.Info("loaded DKIM key",
		"domain", domain,
		"key_path", keyPath,
	)

	return key, nil
}

// Enabled returns whether DKIM signing is enabled.
func (s *DKIMSigner) Enabled() bool {
	return s.config.Enabled
}
