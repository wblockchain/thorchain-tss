package keysign

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gitlab.com/thorchain/tss/monero-wallet-rpc/wallet"

	"gitlab.com/thorchain/tss/go-tss/messages"
	"gitlab.com/thorchain/tss/go-tss/p2p"
)

var signatureNotifierProtocol protocol.ID = "/p2p/signatureNotifier"

type signatureItem struct {
	messageID string
	peerID    peer.ID
	signedTx  *MoneroSpendProof
}

// SignatureNotifier is design to notify the
type SignatureNotifier struct {
	logger       zerolog.Logger
	host         host.Host
	notifierLock *sync.Mutex
	notifiers    map[string]*Notifier
	messages     chan *signatureItem
	streamMgr    *p2p.StreamMgr
}

// NewSignatureNotifier create a new instance of SignatureNotifier
func NewSignatureNotifier(host host.Host) *SignatureNotifier {
	s := &SignatureNotifier{
		logger:       log.With().Str("module", "signature_notifier").Logger(),
		host:         host,
		notifierLock: &sync.Mutex{},
		notifiers:    make(map[string]*Notifier),
		messages:     make(chan *signatureItem),
		streamMgr:    p2p.NewStreamMgr(),
	}
	host.SetStreamHandler(signatureNotifierProtocol, s.handleStream)
	return s
}

// HandleStream handle signature notify stream
func (s *SignatureNotifier) handleStream(stream network.Stream) {
	remotePeer := stream.Conn().RemotePeer()
	logger := s.logger.With().Str("remote peer", remotePeer.String()).Logger()
	logger.Debug().Msg("reading signature notifier message")
	payload, err := p2p.ReadStreamWithBuffer(stream)
	if err != nil {
		logger.Err(err).Msgf("fail to read payload from stream")
		s.streamMgr.AddStream("UNKNOWN", stream)
		return
	}
	// we tell the sender we have received the message
	err = p2p.WriteStreamWithBuffer([]byte("done"), stream)
	if err != nil {
		logger.Error().Err(err).Msgf("fail to write the reply to peer: %s", remotePeer)
	}
	var msg messages.KeysignSignature
	if err := proto.Unmarshal(payload, &msg); err != nil {
		logger.Err(err).Msg("fail to unmarshal join party request")
		s.streamMgr.AddStream("UNKNOWN", stream)
		return
	}
	s.streamMgr.AddStream(msg.ID, stream)
	var signedTxHex MoneroSpendProof
	if len(msg.Signature) > 0 && msg.KeysignStatus == messages.KeysignSignature_Success {
		if err := json.Unmarshal(msg.Signature, &signedTxHex); err != nil {
			logger.Error().Err(err).Msg("fail to unmarshal signature data")
			return
		}
	}
	s.notifierLock.Lock()
	defer s.notifierLock.Unlock()
	n, ok := s.notifiers[msg.ID]
	if !ok {
		logger.Debug().Msgf("notifier for message id(%s) not exist", msg.ID)
		return
	}

	n.threshold -= 1
	finished, err := n.ProcessSignature(&signedTxHex)
	if n.threshold < 1 {
		logger.Error().Err(err).Msg("we have enough nodes report the failure of signature generation")
		n.resp <- nil
		delete(s.notifiers, msg.ID)
		return
	}

	if err != nil {
		logger.Error().Err(err).Msg("fail to verify local signature data")
		return
	}

	if finished {
		delete(s.notifiers, msg.ID)
	}
}

func (s *SignatureNotifier) sendOneMsgToPeer(m *signatureItem) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	stream, err := s.host.NewStream(ctx, m.peerID, signatureNotifierProtocol)
	if err != nil {
		return fmt.Errorf("fail to create stream to peer(%s):%w", m.peerID, err)
	}
	s.logger.Debug().Msgf("open stream to (%s) successfully", m.peerID)
	defer func() {
		s.streamMgr.AddStream(m.messageID, stream)
	}()
	ks := &messages.KeysignSignature{
		ID:            m.messageID,
		KeysignStatus: messages.KeysignSignature_Failed,
	}

	if m.signedTx != nil {
		serialSignedTx, err := json.Marshal(m.signedTx)
		if err != nil {
			return fmt.Errorf("fail to marshal signature data to bytes:%w", err)
		}
		ks.Signature = serialSignedTx
		ks.KeysignStatus = messages.KeysignSignature_Success
	}
	ksBuf, err := proto.Marshal(ks)
	if err != nil {
		return fmt.Errorf("fail to marshal Keysign Signature to bytes:%w", err)
	}
	err = p2p.WriteStreamWithBuffer(ksBuf, stream)
	if err != nil {
		return fmt.Errorf("fail to write message to stream:%w", err)
	}
	// we wait for 1 second to allow the receive notify us
	if err := stream.SetReadDeadline(time.Now().Add(time.Second * 1)); nil != err {
		return err
	}
	ret := make([]byte, 8)
	_, err = stream.Read(ret)
	return err
}

// BroadcastSignature sending the keysign signature to all other peers
func (s *SignatureNotifier) BroadcastSignature(messageID string, signedTxHex *MoneroSpendProof, peers []peer.ID) error {
	return s.broadcastCommon(messageID, signedTxHex, peers)
}

func (s *SignatureNotifier) broadcastCommon(messageID string, signedTxHex *MoneroSpendProof, peers []peer.ID) error {
	wg := sync.WaitGroup{}
	for _, p := range peers {
		if p == s.host.ID() {
			// don't send the signature to itself
			continue
		}
		signature := &signatureItem{
			messageID: messageID,
			peerID:    p,
			signedTx:  signedTxHex,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.sendOneMsgToPeer(signature)
			if err != nil {
				s.logger.Error().Err(err).Msgf("fail to send signature to peer %s", signature.peerID.String())
			}
		}()
	}
	wg.Wait()
	return nil
}

// BroadcastFailed will send keysign failed message to the nodes that are not in the keysign party
func (s *SignatureNotifier) BroadcastFailed(messageID string, peers []peer.ID) error {
	return s.broadcastCommon(messageID, nil, peers)
}

func (s *SignatureNotifier) addToNotifiers(n *Notifier) {
	s.notifierLock.Lock()
	defer s.notifierLock.Unlock()
	s.notifiers[n.MessageID] = n
}

func (s *SignatureNotifier) removeNotifier(n *Notifier) {
	s.notifierLock.Lock()
	defer s.notifierLock.Unlock()
	delete(s.notifiers, n.MessageID)
}

// WaitForSignature wait until keysign finished and signature is available
func (s *SignatureNotifier) WaitForSignature(messageID string, encodeddest string, walletClient wallet.Client, timeout time.Duration, sigChan chan string, threshold int) (*MoneroSpendProof, error) {
	numWait := threshold/2 + 1
	s.logger.Info().Msgf("we need to wait for %d signature notifications", numWait)
	n, err := NewNotifier(messageID, encodeddest, walletClient, numWait)
	if err != nil {
		return nil, fmt.Errorf("fail to create notifier")
	}
	s.addToNotifiers(n)
	defer s.removeNotifier(n)

	select {
	case d := <-n.GetResponseChannel():
		if d == nil {
			s.logger.Error().Msg("the majority report the failure of the signature generation")
			return nil, errors.New("the majority report the failure of signature generation")
		}
		return d, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout: didn't receive signature after %s", timeout)
	case <-sigChan:
		return nil, p2p.ErrSigGenerated
	}
}

func (s *SignatureNotifier) ReleaseStream(msgID string) {
	s.streamMgr.ReleaseStream(msgID)
}
