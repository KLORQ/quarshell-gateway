package credentialstore

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

// IssuedToken is a short-lived token grant.
type IssuedToken struct {
	Value     string
	ExpiresAt time.Time
	Audience  string
}

// OAuthConfig configures an RFC 8693 token exchange client.
type OAuthConfig struct {
	Endpoint         string
	ClientID         string
	ClientSecret     string
	Audience         string
	HTTPClient       *http.Client
	Timeout          time.Duration
	MaxResponseBytes int64
}

// OAuthExchange performs token exchange against an OAuth authorization server.
type OAuthExchange struct {
	endpoint     string
	clientID     string
	clientSecret string
	audience     string
	client       *http.Client
	maxResponse  int64
}

// NewOAuthExchange validates configuration.
func NewOAuthExchange(config OAuthConfig) (*OAuthExchange, error) {
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return nil, domain.Invalidf("credentials.oauth", "endpoint must be an http(s) URL without credentials")
	}
	if strings.TrimSpace(config.Audience) == "" {
		return nil, domain.Invalidf("credentials.oauth", "audience is required")
	}
	client := config.HTTPClient
	if client == nil {
		timeout := config.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		client = &http.Client{Timeout: timeout}
	}
	maxResponse := config.MaxResponseBytes
	if maxResponse <= 0 {
		maxResponse = 1 << 20
	}
	return &OAuthExchange{
		endpoint: config.Endpoint, clientID: config.ClientID, clientSecret: config.ClientSecret,
		audience: config.Audience, client: client, maxResponse: maxResponse,
	}, nil
}

// Exchange trades a subject token for an access token.
func (e *OAuthExchange) Exchange(ctx context.Context, subjectToken string) (IssuedToken, error) {
	if strings.TrimSpace(subjectToken) == "" {
		return IssuedToken{}, domain.Invalidf("credentials.oauth", "subject token is required")
	}
	form := url.Values{
		"grant_type":    {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_token": {subjectToken},
		"audience":      {e.audience},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return IssuedToken{}, domain.Wrap(err, "credentials.oauth", "build token request")
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	if e.clientID != "" {
		request.SetBasicAuth(e.clientID, e.clientSecret)
	}
	response, err := e.client.Do(request)
	if err != nil {
		return IssuedToken{}, domain.New(domain.CodeUnavailable, "credentials.oauth", "token endpoint unavailable")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, e.maxResponse+1))
	if err != nil {
		return IssuedToken{}, domain.New(domain.CodeUnavailable, "credentials.oauth", "token response unreadable")
	}
	if int64(len(body)) > e.maxResponse {
		return IssuedToken{}, domain.Invalidf("credentials.oauth", "token response exceeds limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if response.StatusCode == http.StatusBadRequest || response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
			return IssuedToken{}, domain.Wrap(domain.ErrPermissionDenied, "credentials.oauth", "token exchange denied")
		}
		return IssuedToken{}, domain.New(domain.CodeUnavailable, "credentials.oauth", "token endpoint error")
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return IssuedToken{}, domain.Invalidf("credentials.oauth", "token response is not valid JSON")
	}
	if payload.AccessToken == "" {
		return IssuedToken{}, domain.Invalidf("credentials.oauth", "token response has no access_token")
	}
	token := IssuedToken{Value: payload.AccessToken, Audience: e.audience}
	if payload.ExpiresIn > 0 {
		token.ExpiresAt = time.Now().Add(time.Duration(payload.ExpiresIn) * time.Second)
	}
	return token, nil
}
