package keysign

import (
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gitlab.com/thorchain/tss/monero-wallet-rpc/wallet"

	"gitlab.com/thorchain/tss/go-tss/monero_multi_sig"
)

// Notifier is design to receive keysign signature, success or failure
type Notifier struct {
	MessageID       string
	resp            chan *MoneroSpendProof
	receiverAddress string
	walletClient    wallet.Client
	logger          zerolog.Logger
}

// NewNotifier create a new instance of Notifier
func NewNotifier(messageID string, receiverAddress string, client wallet.Client) (*Notifier, error) {
	if len(messageID) == 0 {
		return nil, errors.New("messageID is empty")
	}

	if len(receiverAddress) == 0 {
		return nil, errors.New("empty receiver address")
	}

	return &Notifier{
		MessageID:       messageID,
		receiverAddress: receiverAddress,
		resp:            make(chan *MoneroSpendProof, 1),
		walletClient:    client,
		logger:          log.With().Str("module", "signature notifier").Logger(),
	}, nil
}

func (n *Notifier) verifySignature(data *MoneroSpendProof) (bool, error) {
	checkRequest := wallet.RequestCheckTxProof{
		TxID:      data.TransactionID,
		Signature: data.SignatureProof,
		Address:   n.receiverAddress,
	}
	retry := 0
	var err error
	var checkResult bool
	for ; retry < monero_multi_sig.MoneroWalletRetry; retry++ {
		respCheck, err := n.walletClient.CheckTxProof(&checkRequest)
		if err != nil {
			n.logger.Warn().Msgf("we retry (%d) to get the transaction verified", retry)
			time.Sleep(time.Second * 2)
			continue
		}
		checkResult = respCheck.Good
		break
	}

	return checkResult, err
}

// ProcessSignature is to verify whether the signature is valid
// return value bool , true indicated we already gather all the signature from keysign party, and they are all match
// false means we are still waiting for more signature from keysign party
func (n *Notifier) ProcessSignature(data *MoneroSpendProof) (bool, error) {
	if data != nil && data.SignatureProof != "" && data.TransactionID != "" {
		verify, err := n.verifySignature(data)
		if err != nil || !verify {
			return false, fmt.Errorf("fail to verify signature: %w", err)
		}
		n.resp <- data
		return true, nil
	}
	return false, nil
}

// GetResponseChannel the final signature gathered from keysign party will be returned from the channel
func (n *Notifier) GetResponseChannel() <-chan *MoneroSpendProof {
	return n.resp
}
