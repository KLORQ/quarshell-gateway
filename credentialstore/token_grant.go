package credentialstore

import (
	"context"

	"github.com/KLORQ/quarshell-core/domain"
)

// JWTSource fetches a workload identity JWT-SVID for an audience.
type JWTSource interface {
	FetchJWTSVID(context.Context, string) (IssuedToken, error)
}

// TokenGrant exchanges a SPIFFE JWT-SVID for a provider token.
type TokenGrant struct {
	Source   JWTSource
	Exchange *OAuthExchange
}

// Token returns the provider token after one exchange.
func (g *TokenGrant) Token(ctx context.Context) (IssuedToken, error) {
	if g.Source == nil || g.Exchange == nil {
		return IssuedToken{}, domain.Invalidf("credentials.grant", "source and exchange are required")
	}
	subject, err := g.Source.FetchJWTSVID(ctx, g.Exchange.audience)
	if err != nil {
		return IssuedToken{}, err
	}
	if subject.Value == "" {
		return IssuedToken{}, domain.Invalidf("credentials.grant", "source returned an empty SVID")
	}
	return g.Exchange.Exchange(ctx, subject.Value)
}
