package tss

import (
	"gitlab.com/thorchain/tss/go-tss/keygen"
	"gitlab.com/thorchain/tss/go-tss/keysign"
	keyRegroup "gitlab.com/thorchain/tss/go-tss/regroup"
)

// Server define the necessary functionality should be provide by a TSS Server implementation
type Server interface {
	Start() error
	Stop()
	GetLocalPeerID() string
	Keygen(req keygen.Request) (keygen.Response, error)
	KeySign(req keysign.Request) (keysign.Response, error)
	KeyRegroup(req keyRegroup.Request) (keyRegroup.Response, error)
}
