package p2p

import (
	"encoding/hex"
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

func (pc *PartyCoordinator) responseIntegrityCheck(broadcastMsg *messages.JoinPartyLeaderCommBroadcast, src peer.ID) (*messages.JoinPartyLeaderCommBroadcast, error) {
	pc.joinPartyGroupLock.Lock()
	peerGroup, ok := pc.peersGroup[broadcastMsg.ID]
	pc.joinPartyGroupLock.Unlock()
	if !ok {
		pc.logger.Info().Msgf("message ID from unknown peer")
		return nil, errors.New("unknown sender")
	}
	msg, err := proto.Marshal(broadcastMsg)
	if err != nil {
		pc.logger.Error().Err(err).Msg("fail to marshal the broadcast message")
		return nil, err
	}
	encodedBroadcastMsg := hex.EncodeToString(msg)
	peerGroup.peerStatusLock.Lock()

	defer peerGroup.peerStatusLock.Unlock()
	peerGroup.responseMsgMap[src.String()] = encodedBroadcastMsg
	value, freq, err := conversion.GetHighestFreq(peerGroup.responseMsgMap)
	if err != nil {
		pc.logger.Error().Err(err).Msg("fail to get the freq of the response message")
		return nil, err
	}
	if freq >= peerGroup.threshold-1 {
		msgRaw, err := hex.DecodeString(value)
		if err != nil {
			pc.logger.Error().Err(err).Msg("fail to decode the hexed response message")
			return nil, errors.New("fail to decode")
		}
		var retMsg messages.JoinPartyLeaderCommBroadcast
		proto.Unmarshal(msgRaw, &retMsg)
		return &retMsg, nil
	}
	pc.logger.Info().Msgf("--------------->not enough response received with %d,%d", freq, peerGroup.threshold-1)
	return nil, errors.New("not enough response")
}

func (pc *PartyCoordinator) forwardMsg(msg *messages.JoinPartyLeaderCommBroadcast) error {
	pc.joinPartyGroupLock.Lock()
	defer pc.joinPartyGroupLock.Unlock()
	peerGroup, ok := pc.peersGroup[msg.ID]
	if !ok {
		pc.logger.Info().Msgf("message ID from unknown peer")
		return errors.New("unknown sender")
	}
	if peerGroup.hasForwarded == false {
		peerGroup.leaderResponseBroadcast = msg
		peerGroup.notify <- "forward"
		peerGroup.hasForwarded = true
	}
	return nil
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
		// firstly, we verify the signature to ensure the online node list is sent by the leader.
		requestPeers := pc.getRequestPeers(msg.ID, msg.ForwardSignatures)
		if requestPeers == nil {
			pc.logger.Warn().Msg("this response message cannot be verified")
			return
		}
		// the leader do not need to process his own message
		if requestPeers[0] == pc.host.ID() {
			return
		}
		pc.forwardMsg(&msg)
		respMsg, err := pc.responseIntegrityCheck(&msg, stream.Conn().RemotePeer())
		if err != nil {
			return
		}
		// to make it compatible, we convert to the leader version
		convertedMsg := messages.JoinPartyLeaderComm{
			ID:      respMsg.ID,
			MsgType: respMsg.MsgType,
			PeerIDs: respMsg.PeerIDs,
			Type:    messages.JoinPartyLeaderComm_ResponseType(msg.Type),
		}
		pc.processRespMsg(&convertedMsg, stream, requestPeers[0].String())
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
	thisSigMarshaled, err := json.Marshal([]*SigPack{&thisSig})
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
			if peerID == leader && len(msgLeaderSend) != 0 {
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

func (pc *PartyCoordinator) joinPartyMemberBroadcast(msgID string, sig []byte, leader string, allNodes []string, threshold int, sigChan chan string) ([]peer.ID, []peer.ID, error) {
	var allPeers []peer.ID
	for _, el := range allNodes {
		p, err := peer.Decode(el)
		if err != nil {
			return nil, nil, errors.New("fail to decode the peer ID")
		}
		allPeers = append(allPeers, p)
	}
	leaderID, err := peer.Decode(leader)
	if err != nil {
		return nil, nil, errors.New("fail to decode the peer ID")
	}

	peerGroup, err := pc.createJoinPartyGroups(msgID, leader, []string{leader}, threshold)
	if err != nil {
		return nil, nil, fmt.Errorf("fail to create join party:%w", err)
	}

	peerGroup.leader = leader
	peerGroup.peersResponse[leaderID] = true
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
		for {
			select {
			case ret := <-peerGroup.notify:
				switch ret {
				case "taskDone":
					pc.logger.Debug().Msg("we have receive the response from the leader")
					close(done)
					return
				case "forward":
					// now we forward the response to peers
					if peerGroup.leaderResponseBroadcast != nil {
						sentData, err := proto.Marshal(peerGroup.leaderResponseBroadcast)
						if err != nil {
							pc.logger.Error().Err(err).Msg("fail to marshal the response to send")
						}
						pc.broadcastMsgToAll(msgID, sentData, nil, leaderID, allPeers)
					}
					pc.logger.Error().Msg("empty message for forwarding")
				default:
					pc.logger.Info().Msg("unknow notice")
				}
				continue
			// for the broadcast join party, we need extra time for non leader nodes to exchange and check their response
			case <-time.After(pc.timeout + time.Second*2):
				// timeout
				close(done)
				pc.logger.Error().Msg("the leader has not reply us")
				return
			case result := <-sigChan:
				sigNotify = result
				close(done)
				return
			}
		}
	}()
	wg.Wait()
	if peerGroup.leaderResponse == nil {
		leaderPk, err := conversion.GetPubKeyFromPeerID(leader)
		if err != nil {
			pc.logger.Error().Msg("leader is not reachable")
		}
		pc.logger.Error().Msgf("leader(%s) is not reachable", leaderPk)
		return nil, nil, ErrLeaderNotReady
	}

	if sigNotify == "signature received" {
		return nil, nil, ErrSignReceived
	}

	onlineNodes := peerGroup.leaderResponse.PeerIDs
	// we trust the returned nodes returned by the leader, if tss fail, the leader
	// also will get blamed.
	pIDs, err := pc.getPeerIDs(onlineNodes)
	if err != nil {
		pc.logger.Error().Err(err).Msg("fail to parse peer id")
		return nil, nil, err
	}
	var peersIGet []peer.ID
	peerGroup.peerStatusLock.Lock()
	for peerID, val := range peerGroup.peersResponse {
		if val {
			peersIGet = append(peersIGet, peerID)
		}
	}
	peerGroup.peerStatusLock.Unlock()

	if len(pIDs) < threshold {
		return pIDs, peersIGet, errors.New("not enough peer")
	}
	if peerGroup.leaderResponse.Type == messages.JoinPartyLeaderComm_Success {
		return pIDs, peersIGet, nil
	}
	pc.logger.Error().Msg("leader response with join party timeout")
	return pIDs, peersIGet, ErrJoinPartyTimeout
}
