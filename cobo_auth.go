package mcpgrafana

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	coboAuthJWTSecretEnvVar = "COBO_AUTH_JWT_SECRET"

	grafanaAuthModeEnvVar         = "GRAFANA_AUTH_MODE"
	grafanaJWTRSAPrivateKeyEnvVar = "GRAFANA_JWT_RSA_PRIVATE_KEY"
	grafanaJWTKeyIDEnvVar         = "GRAFANA_JWT_KEY_ID"
	grafanaJWTIssuerEnvVar        = "GRAFANA_JWT_ISSUER"
	grafanaJWTAudienceEnvVar      = "GRAFANA_JWT_AUDIENCE"
	grafanaJWTTTLSecondsEnvVar    = "GRAFANA_JWT_TTL_SECONDS"
	grafanaJWTHeaderName          = "X-Cobo-JWT"

	defaultGrafanaJWTKeyID     = "grafana-jwt-key-1"
	defaultGrafanaJWTIssuer    = "grafana_mcp_server"
	defaultGrafanaJWTAudience  = "grafana"
	defaultGrafanaJWTTTLSecond = 60
)

type coboIdentityKey struct{}

// CoboIdentity is the authenticated caller extracted from the Cobo OAuth JWT.
type CoboIdentity struct {
	Email     string
	Name      string
	SessionID string
	Token     string
}

// WithCoboIdentity attaches the authenticated Cobo caller to a context.
func WithCoboIdentity(ctx context.Context, identity CoboIdentity) context.Context {
	return context.WithValue(ctx, coboIdentityKey{}, identity)
}

// CoboIdentityFromContext returns the authenticated Cobo caller from a context.
func CoboIdentityFromContext(ctx context.Context) (CoboIdentity, bool) {
	identity, ok := ctx.Value(coboIdentityKey{}).(CoboIdentity)
	return identity, ok
}

// PropagateCoboIdentityFromRequest copies the inbound HTTP identity into the MCP context.
func PropagateCoboIdentityFromRequest(ctx context.Context, req *http.Request) context.Context {
	if identity, ok := CoboIdentityFromContext(req.Context()); ok {
		return WithCoboIdentity(ctx, identity)
	}
	return ctx
}

// CoboAuthConfig controls inbound MCP JWT validation.
type CoboAuthConfig struct {
	Enabled     bool
	JWTSecret   string
	ExemptPaths []string
}

// CoboAuthMiddleware validates inbound Cobo HS256 bearer tokens for HTTP transports.
func CoboAuthMiddleware(cfg CoboAuthConfig, next http.Handler) http.Handler {
	if !cfg.Enabled {
		return next
	}
	exempt := make(map[string]struct{}, len(cfg.ExemptPaths))
	for _, path := range cfg.ExemptPaths {
		if path != "" {
			exempt[path] = struct{}{}
		}
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		if _, ok := exempt[r.URL.Path]; ok {
			next.ServeHTTP(w, r)
			return
		}
		identity, err := ExtractCoboIdentityFromRequest(r, cfg.JWTSecret)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithCoboIdentity(r.Context(), identity)))
	})
}

// ExtractCoboIdentityFromRequest validates the Authorization bearer token and returns its caller identity.
func ExtractCoboIdentityFromRequest(r *http.Request, secret string) (CoboIdentity, error) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return CoboIdentity{}, errors.New("missing bearer token")
	}
	return ParseCoboIdentity(strings.TrimSpace(auth[len("Bearer "):]), secret)
}

// ParseCoboIdentity validates a Cobo HS256 JWT and extracts the user identity.
func ParseCoboIdentity(tokenString, secret string) (CoboIdentity, error) {
	if strings.TrimSpace(secret) == "" {
		return CoboIdentity{}, errors.New("COBO_AUTH_JWT_SECRET is required")
	}
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method %s", token.Method.Alg())
		}
		return []byte(secret), nil
	}, jwt.WithExpirationRequired())
	if err != nil {
		return CoboIdentity{}, err
	}
	if !token.Valid {
		return CoboIdentity{}, errors.New("invalid token")
	}

	userInfo, _ := claims["user_info"].(map[string]any)
	email, _ := userInfo["email"].(string)
	if email == "" {
		email, _ = claims["email"].(string)
	}
	if email == "" {
		email, _ = claims["sub"].(string)
	}
	if email == "" {
		return CoboIdentity{}, errors.New("missing user email")
	}
	name, _ := userInfo["name"].(string)
	if name == "" {
		name = email
	}
	sessionID, _ := claims["session_id"].(string)

	return CoboIdentity{Email: email, Name: name, SessionID: sessionID, Token: tokenString}, nil
}

// GrafanaJWTConfig controls outbound Grafana auth.jwt token issuance.
type GrafanaJWTConfig struct {
	Enabled    bool
	PrivateKey *rsa.PrivateKey
	KeyID      string
	Issuer     string
	Audience   string
	TTL        time.Duration
}

func (cfg GrafanaJWTConfig) withDefaults() GrafanaJWTConfig {
	if cfg.KeyID == "" {
		cfg.KeyID = defaultGrafanaJWTKeyID
	}
	if cfg.Issuer == "" {
		cfg.Issuer = defaultGrafanaJWTIssuer
	}
	if cfg.Audience == "" {
		cfg.Audience = defaultGrafanaJWTAudience
	}
	if cfg.TTL <= 0 {
		cfg.TTL = time.Duration(defaultGrafanaJWTTTLSecond) * time.Second
	}
	return cfg
}

// IssueGrafanaJWT signs a short-lived RS256 JWT accepted by Grafana auth.jwt.
func IssueGrafanaJWT(identity CoboIdentity, cfg GrafanaJWTConfig) (string, error) {
	cfg = cfg.withDefaults()
	if cfg.PrivateKey == nil {
		return "", errors.New("GRAFANA_JWT_RSA_PRIVATE_KEY is required")
	}
	if identity.Email == "" {
		return "", errors.New("missing Cobo identity email")
	}
	name := identity.Name
	if name == "" {
		name = identity.Email
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":   identity.Email,
		"email": identity.Email,
		"user":  name,
		"iat":   now.Unix(),
		"exp":   now.Add(cfg.TTL).Unix(),
		"iss":   cfg.Issuer,
		"aud":   cfg.Audience,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = cfg.KeyID
	return token.SignedString(cfg.PrivateKey)
}

// GrafanaJWTRoundTripper injects X-Cobo-JWT for Grafana auth.jwt.
type GrafanaJWTRoundTripper struct {
	cfg        GrafanaJWTConfig
	underlying http.RoundTripper
}

func NewGrafanaJWTRoundTripper(rt http.RoundTripper, cfg GrafanaJWTConfig) *GrafanaJWTRoundTripper {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &GrafanaJWTRoundTripper{cfg: cfg.withDefaults(), underlying: rt}
}

func (rt *GrafanaJWTRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	identity, ok := CoboIdentityFromContext(req.Context())
	if !ok {
		return nil, errors.New("Grafana JWT auth requires an authenticated Cobo identity")
	}
	token, err := IssueGrafanaJWT(identity, rt.cfg)
	if err != nil {
		return nil, err
	}
	clonedReq := req.Clone(req.Context())
	clonedReq.Header.Set(grafanaJWTHeaderName, token)
	clonedReq.Header.Del("Authorization")
	return rt.underlying.RoundTrip(clonedReq)
}

func parseRSAPrivateKeyPEM(raw string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, errors.New("invalid PEM private key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return key, nil
}
