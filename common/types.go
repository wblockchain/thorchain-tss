package common

import (
	"time"
)

type TssConfig struct {
	// Party Timeout defines how long do we wait for the party to form
	PartyTimeout time.Duration
	// KeyGenTimeoutSeconds defines how long do we wait the keygen parties to pass messages along
	KeyGenTimeout time.Duration
	// KeySignTimeoutSeconds defines how long do we wait keysign
	KeySignTimeout time.Duration
	// Pre-parameter define the pre-parameter generations timeout
	PreParamTimeout time.Duration
	// enable the tss monitor
	EnableMonitor bool
}

const (
	MoneroSharepre            = "moneroMsgMakeSig"
	MoneroKeyGenShareExchange = "moneroKeyGenShareExchange"
	MoneroExportedSignMsg     = "moneroExportedSignMsg"
	MoneroInitTransfer        = "moneroInitTrnasfer"
	MoneroSignShares          = "moneroSignShares"
	MoneroSignDone            = "moneroSignatureDone"
)

type MoneroShare struct {
	MultisigInfo  string `json:"multisig_info"`
	MsgType       string `json:"message_type"`
	ExchangeRound int    `json:"exchangeRound"`
	// the sender field is only used for keysign
	Sender string `json:"message_sender"`
}
