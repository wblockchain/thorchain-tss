package p2p

import (
	"errors"
	"sync"

	"github.com/libp2p/go-libp2p-core/peer"

	"gitlab.com/thorchain/tss/go-tss/messages"
)

type PeerStatus struct {
	peersResponse           map[peer.ID]bool
	peerStatusLock          *sync.RWMutex
	notify                  chan string
	newFound                chan bool
	leaderResponse          *messages.JoinPartyLeaderComm
	leaderResponseBroadcast *messages.JoinPartyLeaderCommBroadcast
	leader                  string
	threshold               int
	reqCount                int
	peerSigs                []*SigPack
	msgID                   string
	responseMsgMap          map[string]string
	hasForwarded            bool
}

func NewPeerStatus(msgID string, peerNodes []peer.ID, myPeerID peer.ID, leader string, threshold int) *PeerStatus {
	dat := make(map[peer.ID]bool)
	for _, el := range peerNodes {
		if el == myPeerID {
			continue
		}
		dat[el] = false
	}
	peerStatus := &PeerStatus{
		peersResponse:  dat,
		peerStatusLock: &sync.RWMutex{},
		notify:         make(chan string, 1),
		newFound:       make(chan bool, len(peerNodes)),
		leader:         leader,
		threshold:      threshold,
		reqCount:       0,
		peerSigs:       nil,
		msgID:          msgID,
		responseMsgMap: make(map[string]string),
		hasForwarded:   false,
	}
	return peerStatus
}

func (ps *PeerStatus) getCoordinationStatus() bool {
	_, offline := ps.getPeersStatus()
	return len(offline) == 0
}

func (ps *PeerStatus) storeSignatures(signature []*SigPack) {
	ps.peerStatusLock.Lock()
	defer ps.peerStatusLock.Unlock()
	ps.peerSigs = append(ps.peerSigs, signature[:]...)
}

func (ps *PeerStatus) getSignatures() []*SigPack {
	ps.peerStatusLock.Lock()
	defer ps.peerStatusLock.Unlock()
	retVal := make([]*SigPack, len(ps.peerSigs))
	copy(retVal, ps.peerSigs)
	// drop the previous storage
	ps.peerSigs = nil
	return retVal
}

func (ps *PeerStatus) getPeersStatus() ([]peer.ID, []peer.ID) {
	var online []peer.ID
	var offline []peer.ID
	ps.peerStatusLock.RLock()
	defer ps.peerStatusLock.RUnlock()
	for peerNode, val := range ps.peersResponse {
		if val {
			online = append(online, peerNode)
		} else {
			offline = append(offline, peerNode)
		}
	}

	return online, offline
}

func (ps *PeerStatus) updatePeer(peerNode peer.ID) (bool, error) {
	ps.peerStatusLock.Lock()
	defer ps.peerStatusLock.Unlock()
	val, ok := ps.peersResponse[peerNode]
	if !ok {
		return false, errors.New("key not found")
	}

	if ps.leader == "NONE" {
		if !val {
			ps.peersResponse[peerNode] = true
			return true, nil
		}
		return false, nil
	}

	// we already have enough participants
	if ps.reqCount >= ps.threshold {
		return false, nil
	}
	if !val {
		ps.peersResponse[peerNode] = true
		ps.reqCount++
		if ps.reqCount >= ps.threshold {
			return true, nil
		}
	}
	return false, nil
}
