package mcpgrafana

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	coboAuthJWTSecretEnvVar = "COBO_AUTH_JWT_SECRET"
	coboOAuthBaseURLEnvVar  = "COBO_OAUTH_SERVER_BASE_URL"
	oauthBaseURLEnvVar      = "OAUTH_SERVER_BASE_URL"
	coboOAuthProviderEnvVar = "COBO_OAUTH_PROVIDER"
	coboOAuthScopesEnvVar   = "COBO_OAUTH_SCOPES"

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
	defaultCoboOAuthProvider   = "cobo_agent_oauth"
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
	Realm       string
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
			realm := cfg.Realm
			if realm == "" {
				realm = "Grafana MCP"
			}
			metadataURL := requestExternalBaseURL(r) + "/.well-known/oauth-protected-resource"
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(
				`Bearer realm="%s", error="invalid_token", error_description="Authentication required", resource_metadata="%s"`,
				realm,
				metadataURL,
			))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithCoboIdentity(r.Context(), identity)))
	})
}

// OAuthMetadataConfig describes the OAuth authorization server used by MCP clients.
type OAuthMetadataConfig struct {
	ServerBaseURL string
	Provider      string
	Scopes        []string
}

func (cfg OAuthMetadataConfig) withDefaults() OAuthMetadataConfig {
	cfg.ServerBaseURL = strings.TrimRight(strings.TrimSpace(cfg.ServerBaseURL), "/")
	if cfg.Provider == "" {
		cfg.Provider = defaultCoboOAuthProvider
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"profile", "email", "openid"}
	}
	return cfg
}

// OAuthMetadataConfigFromEnv loads Cobo OAuth metadata settings, matching the Python runner env names.
func OAuthMetadataConfigFromEnv() OAuthMetadataConfig {
	baseURL := os.Getenv(coboOAuthBaseURLEnvVar)
	if strings.TrimSpace(baseURL) == "" {
		baseURL = os.Getenv(oauthBaseURLEnvVar)
	}
	return OAuthMetadataConfig{
		ServerBaseURL: baseURL,
		Provider:      os.Getenv(coboOAuthProviderEnvVar),
		Scopes:        strings.Fields(os.Getenv(coboOAuthScopesEnvVar)),
	}.withDefaults()
}

// OAuthProtectedResourceMetadataHandler returns MCP protected resource metadata for OAuth discovery.
func OAuthProtectedResourceMetadataHandler(cfg OAuthMetadataConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metadata, err := OAuthProtectedResourceMetadata(cfg, requestExternalBaseURL(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(metadata); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// OAuthMetadataHandler returns OAuth authorization-server metadata for MCP clients.
func OAuthMetadataHandler(cfg OAuthMetadataConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		metadata, err := OAuthMetadata(cfg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(metadata); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}
}

// OAuthProtectedResourceMetadata describes this MCP server as an OAuth protected resource.
func OAuthProtectedResourceMetadata(cfg OAuthMetadataConfig, resourceURL string) (map[string]any, error) {
	cfg = cfg.withDefaults()
	if cfg.ServerBaseURL == "" {
		return nil, errors.New("OAUTH_SERVER_BASE_URL is required")
	}
	return map[string]any{
		"resource":              strings.TrimRight(strings.TrimSpace(resourceURL), "/"),
		"authorization_servers": []string{cfg.ServerBaseURL},
		"scopes_supported":      cfg.Scopes,
		"bearer_methods_supported": []string{
			"header",
		},
	}, nil
}

// OAuthMetadata returns the same provider-facing metadata shape used by the Python MCP runner.
func OAuthMetadata(cfg OAuthMetadataConfig) (map[string]any, error) {
	cfg = cfg.withDefaults()
	if cfg.ServerBaseURL == "" {
		return nil, errors.New("OAUTH_SERVER_BASE_URL is required")
	}
	return map[string]any{
		"issuer":                                cfg.ServerBaseURL,
		"authorization_endpoint":                fmt.Sprintf("%s/oauth/authorize/%s", cfg.ServerBaseURL, cfg.Provider),
		"token_endpoint":                        fmt.Sprintf("%s/oauth/token", cfg.ServerBaseURL),
		"userinfo_endpoint":                     fmt.Sprintf("%s/oauth/userinfo", cfg.ServerBaseURL),
		"registration_endpoint":                 fmt.Sprintf("%s/oauth/register", cfg.ServerBaseURL),
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
		"scopes_supported":                      cfg.Scopes,
		"code_challenge_methods_supported":      []string{"S256", "plain"},
		"ui_locales_supported":                  []string{"en", "zh"},
		"response_modes_supported":              []string{"query"},
	}, nil
}

func requestExternalBaseURL(r *http.Request) string {
	proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	if host == "" {
		host = "localhost"
	}
	return strings.TrimRight(proto+"://"+host, "/")
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
