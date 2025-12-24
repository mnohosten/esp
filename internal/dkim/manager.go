// Package dkim provides DKIM key management and signing functionality.
package dkim

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// KeyManager handles DKIM key generation and storage.
type KeyManager struct {
	keyDir   string
	selector string
	keyBits  int
	logger   *slog.Logger

	// Cache for loaded keys
	keyCache   map[string]*rsa.PrivateKey
	keyCacheMu sync.RWMutex
}

// KeyInfo contains information about a DKIM key.
type KeyInfo struct {
	Domain     string
	Selector   string
	PrivateKey *rsa.PrivateKey
	PublicKey  string // Base64-encoded public key for DNS
	DNSRecord  string // Full DNS TXT record value
	DNSName    string // DNS record name (selector._domainkey.domain)
}

// NewKeyManager creates a new DKIM key manager.
func NewKeyManager(keyDir, selector string, logger *slog.Logger) (*KeyManager, error) {
	// Ensure key directory exists
	if err := os.MkdirAll(keyDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	return &KeyManager{
		keyDir:   keyDir,
		selector: selector,
		keyBits:  2048, // Standard RSA key size for DKIM
		logger:   logger.With("component", "dkim.manager"),
		keyCache: make(map[string]*rsa.PrivateKey),
	}, nil
}

// GenerateKey generates a new DKIM key pair for a domain.
func (m *KeyManager) GenerateKey(domain string) (*KeyInfo, error) {
	m.logger.Info("generating DKIM key", "domain", domain, "selector", m.selector)

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, m.keyBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Save private key to file
	keyPath := m.keyPath(domain)
	if err := m.savePrivateKey(keyPath, privateKey); err != nil {
		return nil, fmt.Errorf("failed to save private key: %w", err)
	}

	// Cache the key
	m.keyCacheMu.Lock()
	m.keyCache[domain] = privateKey
	m.keyCacheMu.Unlock()

	// Generate public key info
	info := m.buildKeyInfo(domain, privateKey)

	m.logger.Info("DKIM key generated",
		"domain", domain,
		"selector", m.selector,
		"key_path", keyPath,
		"dns_name", info.DNSName,
	)

	return info, nil
}

// GetKey retrieves an existing DKIM key for a domain.
func (m *KeyManager) GetKey(domain string) (*KeyInfo, error) {
	// Check cache first
	m.keyCacheMu.RLock()
	if key, ok := m.keyCache[domain]; ok {
		m.keyCacheMu.RUnlock()
		return m.buildKeyInfo(domain, key), nil
	}
	m.keyCacheMu.RUnlock()

	// Load from file
	keyPath := m.keyPath(domain)
	privateKey, err := m.loadPrivateKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load key for %s: %w", domain, err)
	}

	// Cache it
	m.keyCacheMu.Lock()
	m.keyCache[domain] = privateKey
	m.keyCacheMu.Unlock()

	return m.buildKeyInfo(domain, privateKey), nil
}

// KeyExists checks if a DKIM key exists for a domain.
func (m *KeyManager) KeyExists(domain string) bool {
	keyPath := m.keyPath(domain)
	_, err := os.Stat(keyPath)
	return err == nil
}

// RotateKey generates a new DKIM key, keeping the old one as backup.
func (m *KeyManager) RotateKey(domain string) (*KeyInfo, error) {
	keyPath := m.keyPath(domain)
	backupPath := keyPath + ".old"

	// Backup existing key if it exists
	if _, err := os.Stat(keyPath); err == nil {
		if err := os.Rename(keyPath, backupPath); err != nil {
			m.logger.Warn("failed to backup old key", "error", err)
		}
	}

	// Remove from cache
	m.keyCacheMu.Lock()
	delete(m.keyCache, domain)
	m.keyCacheMu.Unlock()

	// Generate new key
	return m.GenerateKey(domain)
}

// DeleteKey removes the DKIM key for a domain.
func (m *KeyManager) DeleteKey(domain string) error {
	keyPath := m.keyPath(domain)

	// Remove from cache
	m.keyCacheMu.Lock()
	delete(m.keyCache, domain)
	m.keyCacheMu.Unlock()

	// Remove file
	if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete key file: %w", err)
	}

	m.logger.Info("DKIM key deleted", "domain", domain)
	return nil
}

// GetDNSRecord returns the DNS TXT record content for a domain's DKIM key.
func (m *KeyManager) GetDNSRecord(domain string) (string, string, error) {
	info, err := m.GetKey(domain)
	if err != nil {
		return "", "", err
	}
	return info.DNSName, info.DNSRecord, nil
}

// keyPath returns the file path for a domain's private key.
func (m *KeyManager) keyPath(domain string) string {
	filename := fmt.Sprintf("%s.%s.key", domain, m.selector)
	return filepath.Join(m.keyDir, filename)
}

// savePrivateKey saves a private key to a PEM file.
func (m *KeyManager) savePrivateKey(path string, key *rsa.PrivateKey) error {
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	}

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	return pem.Encode(file, pemBlock)
}

// loadPrivateKey loads a private key from a PEM file.
func (m *KeyManager) loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA key")
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

// buildKeyInfo creates a KeyInfo from a private key.
func (m *KeyManager) buildKeyInfo(domain string, key *rsa.PrivateKey) *KeyInfo {
	// Encode public key for DNS
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		m.logger.Error("failed to marshal public key", "error", err)
		return nil
	}
	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

	// Build DNS TXT record value
	// For long keys, this may need to be split across multiple strings
	dnsRecord := fmt.Sprintf("v=DKIM1; k=rsa; p=%s", pubKeyBase64)

	return &KeyInfo{
		Domain:     domain,
		Selector:   m.selector,
		PrivateKey: key,
		PublicKey:  pubKeyBase64,
		DNSRecord:  dnsRecord,
		DNSName:    fmt.Sprintf("%s._domainkey.%s", m.selector, domain),
	}
}

// Selector returns the configured DKIM selector.
func (m *KeyManager) Selector() string {
	return m.selector
}

// KeyDir returns the key storage directory.
func (m *KeyManager) KeyDir() string {
	return m.keyDir
}

// FormatDNSRecordForDisplay formats a DKIM DNS record for display.
// Long records are split into multiple quoted strings as per RFC requirements.
func FormatDNSRecordForDisplay(record string) string {
	// DKIM records over 255 characters need to be split
	if len(record) <= 255 {
		return fmt.Sprintf(`"%s"`, record)
	}

	// Split into 255-char chunks
	var parts []string
	for len(record) > 0 {
		end := 255
		if end > len(record) {
			end = len(record)
		}
		parts = append(parts, fmt.Sprintf(`"%s"`, record[:end]))
		record = record[end:]
	}
	return strings.Join(parts, " ")
}
