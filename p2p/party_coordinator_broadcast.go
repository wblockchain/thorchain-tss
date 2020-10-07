package p2p

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"

	"google.golang.org/protobuf/proto"

	"gitlab.com/thorchain/tss/go-tss/conversion"
	"gitlab.com/thorchain/tss/go-tss/messages"
)

type SigPack struct {
	Sig    []byte
	PeerID peer.ID
}

// hHandleStreamWithLeaderBroadcast handle party coordinate stream
func (pc *PartyCoordinator) HandleStreamWithLeaderBroadcast(stream network.Stream) {
	remotePeer := stream.Conn().RemotePeer()
	logger := pc.logger.With().Str("remote peer", remotePeer.String()).Logger()
	logger.Debug().Msg("reading from join party request")
	payload, err := ReadStreamWithBuffer(stream)
	if err != nil {
		logger.Err(err).Msgf("fail to read payload from stream")
		pc.streamMgr.AddStream("UNKNOWN", stream)
		return
	}

	var msg messages.JoinPartyLeaderCommBroadcast
	err = proto.Unmarshal(payload, &msg)
	if err != nil {
		logger.Err(err).Msg("fail to unmarshal party data")
		pc.streamMgr.AddStream("UNKNOWN", stream)
		return
	}
	switch msg.MsgType {
	case "request":
		pc.processBroadcastReqMsg(&msg, stream)
		return
	case "response":
		// to make it compatible, we convert to the leader version
		convertedMsg := messages.JoinPartyLeaderComm{
			ID:      msg.ID,
			MsgType: msg.MsgType,
			PeerIDs: msg.PeerIDs,
			Type:    messages.JoinPartyLeaderComm_ResponseType(msg.Type),
		}
		pc.processRespMsg(&convertedMsg, stream)
		return
	default:
		logger.Err(err).Msg("fail to process this message")
		pc.streamMgr.AddStream("UNKNOWN", stream)
		return
	}
}

func generateMSgForSending(msgID string, sig []byte, forwarded []*SigPack, pid peer.ID) ([]byte, []byte, error) {
	thisSig := SigPack{
		sig,
		pid,
	}
	// we put ourself first then the forwarded msg to enable the leader process our request firstly
	sendSignatures := append([]*SigPack{&thisSig}, forwarded[:]...)
	signaturesMarshaledForLeader, err := json.Marshal(sendSignatures)
	if err != nil {
		return nil, nil, err
	}
	thisSigMarshaled, err := json.Marshal([]SigPack{thisSig})
	if err != nil {
		return nil, nil, err
	}
	msgLeader := messages.JoinPartyLeaderCommBroadcast{
		ID:                msgID,
		MsgType:           "request",
		ForwardSignatures: signaturesMarshaledForLeader,
	}

	msgPeer := messages.JoinPartyLeaderCommBroadcast{
		ID:                msgID,
		MsgType:           "request",
		ForwardSignatures: thisSigMarshaled,
	}

	marshaledMsgPeer, err := proto.Marshal(&msgPeer)
	if err != nil {
		return nil, nil, err
	}

	marshaledMsgLeader, err := proto.Marshal(&msgLeader)
	if err != nil {
		return nil, nil, err
	}
	return marshaledMsgPeer, marshaledMsgLeader, nil
}

func (pc *PartyCoordinator) broadcastMsgToAll(msgID string, msgPeerSend, msgLeaderSend []byte, leader peer.ID, peers []peer.ID) {
	var wg sync.WaitGroup
	wg.Add(len(peers))
	for _, el := range peers {
		go func(peerID peer.ID) {
			defer wg.Done()
			if peerID == pc.host.ID() {
				return
			}
			if peerID == leader {
				if err := pc.sendMsgToPeer(msgLeaderSend, msgID, peerID, joinPartyProtocolWithLeaderBroadcast); err != nil {
					pc.logger.Error().Err(err).Msg("error in send the join party request to peer")
				}
				return
			}
			if err := pc.sendMsgToPeer(msgPeerSend, msgID, peerID, joinPartyProtocolWithLeaderBroadcast); err != nil {
				pc.logger.Error().Err(err).Msg("error in send the join party request to peer")
			}
		}(el)
	}
	wg.Wait()
}

func (pc *PartyCoordinator) joinPartyMemberBroadcast(msgID string, sig []byte, leader string, allNodes []string, threshold int, sigChan chan string) ([]peer.ID, error) {
	var allPeers []peer.ID
	for _, el := range allNodes {
		p, err := peer.Decode(el)
		if err != nil {
			return nil, errors.New("fail to decode the peer ID")
		}
		allPeers = append(allPeers, p)
	}

	peerGroup, err := pc.createJoinPartyGroups(msgID, leader, []string{leader}, threshold)
	if err != nil {
		return nil, fmt.Errorf("fail to create join party:%w", err)
	}

	peerGroup.leader = leader
	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
				// we send to leader the join party members with forward
				// while the peer just ourself to avoid the broadcast storm
				peerSignatures := peerGroup.getSignatures()
				msgPeerSend, msgLeaderSend, err := generateMSgForSending(msgID, sig, peerSignatures, pc.host.ID())
				if err != nil {
					pc.logger.Error().Err(err).Msg("fail to generate the message for sending")
					continue
				}
				leaderID, err := peer.Decode(leader)
				if err != nil {
					pc.logger.Error().Err(err).Msg("fail to decode the peer ID")
					continue
				}

				pc.broadcastMsgToAll(msgID, msgPeerSend, msgLeaderSend, leaderID, allPeers)
			}
			time.Sleep(time.Millisecond * 500)
		}
	}()
	// this is the total time TSS will wait for the party to form
	var sigNotify string
	wg.Add(1)
	go func() {
		defer wg.Done()
		// now we wait for the leader to notify us who we do the keygen/keysign with
		select {
		case <-peerGroup.notify:
			pc.logger.Debug().Msg("we have receive the response from the leader")
			close(done)
			return

		case <-time.After(pc.timeout):
			// timeout
			close(done)
			pc.logger.Error().Msg("the leader has not reply us")
			return
		case result := <-sigChan:
			sigNotify = result
			close(done)
			return
		}
	}()
	wg.Wait()
	if peerGroup.leaderResponse == nil {
		leaderPk, err := conversion.GetPubKeyFromPeerID(leader)
		if err != nil {
			pc.logger.Error().Msg("leader is not reachable")
		}
		pc.logger.Error().Msgf("leader(%s) is not reachable", leaderPk)
		return nil, ErrLeaderNotReady
	}

	if sigNotify == "signature received" {
		return nil, ErrSignReceived
	}

	onlineNodes := peerGroup.leaderResponse.PeerIDs
	// we trust the returned nodes returned by the leader, if tss fail, the leader
	// also will get blamed.
	pIDs, err := pc.getPeerIDs(onlineNodes)
	if err != nil {
		pc.logger.Error().Err(err).Msg("fail to parse peer id")
		return nil, err
	}
	if len(pIDs) < threshold {
		return pIDs, errors.New("not enough peer")
	}

	if peerGroup.leaderResponse.Type == messages.JoinPartyLeaderComm_Success {
		return pIDs, nil
	}
	pc.logger.Error().Msg("leader response with join party timeout")
	return pIDs, ErrJoinPartyTimeout
}
