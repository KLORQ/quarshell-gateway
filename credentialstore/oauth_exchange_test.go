package credentialstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

func TestOAuthExchangeSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("content type = %q", request.Header.Get("Content-Type"))
		}
		user, password, ok := request.BasicAuth()
		if !ok || user != "client" || password != "secret" {
			t.Errorf("basic auth = %q/%q ok=%v", user, password, ok)
		}
		_ = request.ParseForm()
		if request.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" ||
			request.Form.Get("subject_token") != "subject" ||
			request.Form.Get("audience") != "api" {
			t.Errorf("form = %v", request.Form)
		}
		_, _ = writer.Write([]byte(`{"access_token":"issued","expires_in":60}`))
	}))
	defer server.Close()
	exchange, err := NewOAuthExchange(OAuthConfig{
		Endpoint: server.URL, ClientID: "client", ClientSecret: "secret", Audience: "api",
	})
	if err != nil {
		t.Fatalf("NewOAuthExchange: %v", err)
	}
	token, err := exchange.Exchange(context.Background(), "subject")
	if err != nil || token.Value != "issued" || token.Audience != "api" {
		t.Fatalf("token = %+v %v", token, err)
	}
	if token.ExpiresAt.Before(time.Now()) {
		t.Fatalf("expiry = %s", token.ExpiresAt)
	}
}

func TestOAuthExchangeErrors(t *testing.T) {
	for name, status := range map[string]int{
		"denied":      http.StatusBadRequest,
		"forbidden":   http.StatusForbidden,
		"unavailable": http.StatusInternalServerError,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.WriteHeader(status)
			}))
			defer server.Close()
			exchange, _ := NewOAuthExchange(OAuthConfig{Endpoint: server.URL, Audience: "api"})
			_, err := exchange.Exchange(context.Background(), "subject")
			if status == http.StatusInternalServerError {
				if !errors.Is(err, domain.ErrUnavailable) {
					t.Fatalf("unavailable = %v", err)
				}
				return
			}
			if !errors.Is(err, domain.ErrPermissionDenied) {
				t.Fatalf("denied = %v", err)
			}
		})
	}
}

func TestOAuthExchangeBoundsAndValidation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("x", 2048)))
	}))
	defer server.Close()
	exchange, _ := NewOAuthExchange(OAuthConfig{Endpoint: server.URL, Audience: "api", MaxResponseBytes: 64})
	if _, err := exchange.Exchange(context.Background(), "subject"); err == nil {
		t.Fatalf("oversized response accepted")
	}
	if _, err := exchange.Exchange(context.Background(), " "); err == nil {
		t.Fatalf("empty subject accepted")
	}
	if _, err := NewOAuthExchange(OAuthConfig{Endpoint: "ftp://idp", Audience: "api"}); err == nil {
		t.Fatalf("invalid endpoint accepted")
	}
	if _, err := NewOAuthExchange(OAuthConfig{Endpoint: "http://idp", Audience: " "}); err == nil {
		t.Fatalf("empty audience accepted")
	}
}

func TestOAuthExchangeTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	defer server.Close()
	exchange, _ := NewOAuthExchange(OAuthConfig{Endpoint: server.URL, Audience: "api", Timeout: 20 * time.Millisecond})
	if _, err := exchange.Exchange(context.Background(), "subject"); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("timeout = %v", err)
	}
}
