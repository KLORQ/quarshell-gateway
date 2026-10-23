// Package credentialstore contains Gateway credential persistence and exchange adapters.
package credentialstore

import corecredentials "github.com/KLORQ/quarshell-core/credentials"

type (
	MemoryStore     = corecredentials.MemoryStore
	Secret          = corecredentials.Secret
	EndpointBinding = corecredentials.EndpointBinding
	Store           = corecredentials.Store
	Handle          = corecredentials.Handle
	HandleInfo      = corecredentials.HandleInfo
	IssueRequest    = corecredentials.IssueRequest
	Broker          = corecredentials.Broker
	Rewriter        = corecredentials.Rewriter
	RewriteTarget   = corecredentials.RewriteTarget
)

const Placeholder = corecredentials.Placeholder

const (
	RewriteBody   = corecredentials.RewriteBody
	RewriteHeader = corecredentials.RewriteHeader
)

var (
	NewMemoryStore = corecredentials.NewMemoryStore
	NewBroker      = corecredentials.NewBroker
)
