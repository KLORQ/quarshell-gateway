package credentialstore

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
)

type fakeJWTSource struct {
	value string
	err   error
}

func (f fakeJWTSource) FetchJWTSVID(context.Context, string) (IssuedToken, error) {
	return IssuedToken{Value: f.value}, f.err
}

func TestTokenGrantExchangesSVID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_ = request.ParseForm()
		if request.Form.Get("subject_token") != "svid" {
			t.Errorf("subject = %q", request.Form.Get("subject_token"))
		}
		_, _ = writer.Write([]byte(`{"access_token":"provider-token","expires_in":60}`))
	}))
	defer server.Close()
	exchange, _ := NewOAuthExchange(OAuthConfig{Endpoint: server.URL, Audience: "provider"})
	grant := &TokenGrant{Source: fakeJWTSource{value: "svid"}, Exchange: exchange}
	token, err := grant.Token(context.Background())
	if err != nil || token.Value != "provider-token" {
		t.Fatalf("token = %+v %v", token, err)
	}
}

func TestTokenGrantRejectsFailure(t *testing.T) {
	exchange, _ := NewOAuthExchange(OAuthConfig{Endpoint: "http://127.0.0.1:1", Audience: "provider"})
	grant := &TokenGrant{Source: fakeJWTSource{err: errors.New("no svid")}, Exchange: exchange}
	if _, err := grant.Token(context.Background()); err == nil {
		t.Fatalf("source failure accepted")
	}
	if _, err := (&TokenGrant{Exchange: exchange}).Token(context.Background()); !errors.Is(err, domain.ErrInvalid) && err == nil {
		t.Fatalf("missing source accepted")
	}
}
