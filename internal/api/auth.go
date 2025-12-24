package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// contextKey is a custom type for context keys.
type contextKey string

const (
	// ClaimsContextKey is the context key for JWT claims.
	ClaimsContextKey contextKey = "claims"
)

// Claims represents JWT claims.
type Claims struct {
	UserID   uuid.UUID `json:"user_id"`
	Email    string    `json:"email"`
	DomainID uuid.UUID `json:"domain_id"`
	IsAdmin  bool      `json:"is_admin"`
	jwt.RegisteredClaims
}

// JWTAuth handles JWT authentication.
type JWTAuth struct {
	secret []byte
	expiry time.Duration
	apiKey string
}

// NewJWTAuth creates a new JWT authenticator.
func NewJWTAuth(secret string, expiry time.Duration) *JWTAuth {
	return &JWTAuth{
		secret: []byte(secret),
		expiry: expiry,
	}
}

// SetAPIKey sets an API key for admin access.
func (j *JWTAuth) SetAPIKey(apiKey string) {
	j.apiKey = apiKey
}

// GenerateToken generates a new JWT token.
func (j *JWTAuth) GenerateToken(userID uuid.UUID, email string, domainID uuid.UUID, isAdmin bool) (string, time.Time, error) {
	expiresAt := time.Now().Add(j.expiry)

	claims := &Claims{
		UserID:   userID,
		Email:    email,
		DomainID: domainID,
		IsAdmin:  isAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "esp",
			Subject:   userID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(j.secret)
	if err != nil {
		return "", time.Time{}, err
	}

	return tokenString, expiresAt, nil
}

// ValidateToken validates and parses a JWT token.
func (j *JWTAuth) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return j.secret, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

// Middleware returns authentication middleware.
// Supports both Bearer token (JWT) and X-API-Key header authentication.
func (j *JWTAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var claims *Claims

		// Check for API key first (admin access)
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != "" {
			if j.apiKey == "" {
				respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "API key authentication not configured")
				return
			}
			if apiKey != j.apiKey {
				respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid API key")
				return
			}
			// API key grants admin access
			claims = &Claims{
				UserID:   uuid.Nil,
				Email:    "api@localhost",
				DomainID: uuid.Nil,
				IsAdmin:  true,
			}
		} else {
			// Fall back to JWT authentication
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing authorization header")
				return
			}

			// Extract token from "Bearer <token>"
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid authorization header format")
				return
			}

			var err error
			claims, err = j.ValidateToken(parts[1])
			if err != nil {
				respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid or expired token")
				return
			}
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AdminMiddleware requires admin privileges.
func AdminMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetClaims(r.Context())
		if claims == nil {
			respondError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
			return
		}

		if !claims.IsAdmin {
			respondError(w, http.StatusForbidden, "FORBIDDEN", "admin privileges required")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GetClaims extracts claims from context.
func GetClaims(ctx context.Context) *Claims {
	claims, ok := ctx.Value(ClaimsContextKey).(*Claims)
	if !ok {
		return nil
	}
	return claims
}
