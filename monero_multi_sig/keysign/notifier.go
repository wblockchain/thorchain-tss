package keysign

import (
	"errors"
	"fmt"

	"gitlab.com/thorchain/tss/monero-wallet-rpc/wallet"
)

// Notifier is design to receive keysign signature, success or failure
type Notifier struct {
	MessageID       string
	message         []byte // the message
	resp            chan *MoneroSpendProof
	receiverAddress string
	walletClient    wallet.Client
}

// NewNotifier create a new instance of Notifier
func NewNotifier(messageID string, message []byte, receiverAddress string, client wallet.Client) (*Notifier, error) {
	if len(messageID) == 0 {
		return nil, errors.New("messageID is empty")
	}
	if len(message) == 0 {
		return nil, errors.New("message is nil")
	}
	if len(receiverAddress) == 0 {
		return nil, errors.New("empty receiver address")
	}

	return &Notifier{
		MessageID:       messageID,
		message:         message,
		receiverAddress: receiverAddress,
		resp:            make(chan *MoneroSpendProof, 1),
		walletClient:    client,
	}, nil
}

func (n *Notifier) verifySignature(data *MoneroSpendProof) (bool, error) {
	checkRequest := wallet.RequestCheckTxProof{
		TxID:      data.TransactionID,
		Signature: data.SignatureProof,
		Address:   n.receiverAddress,
	}
	respCheck, err := n.walletClient.CheckTxProof(&checkRequest)
	return respCheck.Good, err
}

// ProcessSignature is to verify whether the signature is valid
// return value bool , true indicated we already gather all the signature from keysign party, and they are all match
// false means we are still waiting for more signature from keysign party
func (n *Notifier) ProcessSignature(data *MoneroSpendProof) (bool, error) {
	if data != nil {
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
