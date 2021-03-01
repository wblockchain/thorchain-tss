package keysign

import (
	"encoding/base64"
	"encoding/json"
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
	MessageID      string
	resp           chan *MoneroSpendProof
	encodedAddress string
	txSend         *wallet.RequestTransfer
	walletClient   wallet.Client
	logger         zerolog.Logger
	threshold      int
}

// NewNotifier create a new instance of Notifier
func NewNotifier(messageID string, encodedAddress string, client wallet.Client, threshold int) (*Notifier, error) {
	if len(messageID) == 0 {
		return nil, errors.New("messageID is empty")
	}

	tx, err := base64.StdEncoding.DecodeString(encodedAddress)
	if err != nil {
		return nil, err
	}
	var txSend wallet.RequestTransfer
	err = json.Unmarshal(tx, &txSend)
	if err != nil {
		return nil, err
	}

	return &Notifier{
		MessageID:      messageID,
		encodedAddress: encodedAddress,
		resp:           make(chan *MoneroSpendProof, 1),
		walletClient:   client,
		txSend:         &txSend,
		logger:         log.With().Str("module", "signature notifier").Logger(),
		threshold:      threshold,
	}, nil
}

func (n *Notifier) checkEachTransaction(dest *wallet.Destination, req wallet.RequestCheckTxKey) (bool, error) {
	retry := 0
	var err error
	var respCheck *wallet.ResponseCheckTxKey
	for ; retry < monero_multi_sig.MoneroWalletRetry; retry++ {
		respCheck, err = n.walletClient.CheckTxKey(&req)
		if err != nil {
			n.logger.Warn().Msgf("we retry (%d) to get the transaction verified with error %v", retry, err)
			time.Sleep(time.Second * 2)
			continue
		}
		if respCheck.Received == dest.Amount {
			return true, nil
		}
	}
	return false, nil
}

func (n *Notifier) verifySignature(data *MoneroSpendProof) (bool, error) {
	var err error

	dests := n.txSend.Destinations
	for _, dest := range dests {
		req := wallet.RequestCheckTxKey{
			TxID:    data.TransactionID,
			TxKey:   data.TxKey,
			Address: dest.Address,
		}
		ret, err := n.checkEachTransaction(dest, req)
		if err != nil {
			return false, err
		}
		if !ret {
			return ret, nil
		}
	}
	return true, err
}

// ProcessSignature is to verify whether the signature is valid
// return value bool , true indicated we already gather all the signature from keysign party, and they are all match
// false means we are still waiting for more signature from keysign party
func (n *Notifier) ProcessSignature(data *MoneroSpendProof) (bool, error) {
	if data != nil && data.TxKey != "" && data.TransactionID != "" {

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
