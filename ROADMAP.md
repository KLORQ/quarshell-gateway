# Roadmap — quarshell-gateway

Status: pre-stable API · Current module tag: `v0.1.1` · Dependencies are listed in `go.mod`.

## This module

| ID | Item | Notes |
|----|------|-------|
| G1 | **Auth** | OIDC / mTLS for agents and CLI |
| G2 | **Proposals API** | Complete store/approve/reject + CLI `quarshell rule` |
| G3 | **Helm / image** | Versioned chart + `ghcr.io/klorq/quarshell/gateway` |
| G4 | **Relay polish** | Long-poll exec reliability under load |


## Release

This module follows its own pre-stable 0.x version sequence. Publish dependencies
first, update consumers to the published tags, and verify with `GOWORK=off`. Never
rewrite a published tag.
