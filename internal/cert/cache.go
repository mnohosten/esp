package cert

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/crypto/acme/autocert"
)

// FileCache stores certificates on disk.
// It implements the autocert.Cache interface.
type FileCache struct {
	dir string
}

// NewFileCache creates a new file-based certificate cache.
func NewFileCache(dir string) (*FileCache, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &FileCache{dir: dir}, nil
}

// Get reads a certificate data for the specified key.
func (c *FileCache) Get(ctx context.Context, key string) ([]byte, error) {
	path := filepath.Join(c.dir, sanitizeKey(key))

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, autocert.ErrCacheMiss
	}
	if err != nil {
		return nil, err
	}

	return data, nil
}

// Put writes certificate data for the specified key.
func (c *FileCache) Put(ctx context.Context, key string, data []byte) error {
	path := filepath.Join(c.dir, sanitizeKey(key))
	return os.WriteFile(path, data, 0600)
}

// Delete removes certificate data for the specified key.
func (c *FileCache) Delete(ctx context.Context, key string) error {
	path := filepath.Join(c.dir, sanitizeKey(key))
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// sanitizeKey converts a cache key to a safe filename.
func sanitizeKey(key string) string {
	// Replace any path separators to prevent directory traversal
	result := make([]byte, 0, len(key))
	for i := 0; i < len(key); i++ {
		c := key[i]
		if c == '/' || c == '\\' || c == ':' {
			result = append(result, '_')
		} else {
			result = append(result, c)
		}
	}
	return string(result)
}

// Dir returns the cache directory.
func (c *FileCache) Dir() string {
	return c.dir
}
