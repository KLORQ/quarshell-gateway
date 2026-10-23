package credentialstore

import (
	"context"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// SpiffeJWTSource fetches JWT-SVIDs from a SPIRE Workload API socket.
type SpiffeJWTSource struct {
	Socket string
}

// FetchJWTSVID returns a JWT-SVID for the audience.
func (s *SpiffeJWTSource) FetchJWTSVID(ctx context.Context, audience string) (IssuedToken, error) {
	options := []workloadapi.ClientOption{}
	if s.Socket != "" {
		options = append(options, workloadapi.WithAddr("unix://"+s.Socket))
	}
	svid, err := workloadapi.FetchJWTSVID(ctx, jwtsvid.Params{Audience: audience}, options...)
	if err != nil {
		return IssuedToken{}, domain.New(domain.CodeUnavailable, "credentials.spiffe", "workload API unavailable")
	}
	return IssuedToken{Value: svid.Marshal(), ExpiresAt: svid.Expiry, Audience: audience}, nil
}
