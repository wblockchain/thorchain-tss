package keysign

import (
	"gitlab.com/thorchain/tss/go-tss/blame"
	"gitlab.com/thorchain/tss/go-tss/common"
)

// Response key sign response
type Response struct {
	SignedTxHex string        `json:"signed_tx_hex"`
	TxKey       string        `json:"tx_key"`
	Status      common.Status `json:"status"`
	Blame       blame.Blame   `json:"blame"`
}

func NewResponse(signedTxHex, txKey string, status common.Status, blame blame.Blame) Response {
	return Response{
		SignedTxHex: signedTxHex,
		TxKey:       txKey,
		Status:      status,
		Blame:       blame,
	}
}
