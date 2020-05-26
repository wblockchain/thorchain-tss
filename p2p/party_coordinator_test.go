package p2p

import (
	"context"
	"math/rand"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/protocol"
	tnet "github.com/libp2p/go-libp2p-testing/net"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/stretchr/testify/assert"

	"gitlab.com/thorchain/tss/go-tss/conversion"
	"gitlab.com/thorchain/tss/go-tss/messages"
)

func setupHosts(t *testing.T, n int) []host.Host {
	mn := mocknet.New(context.Background())
	var hosts []host.Host
	for i := 0; i < n; i++ {

		id := tnet.RandIdentityOrFatal(t)
		a := tnet.RandLocalTCPAddress()
		h, err := mn.AddPeer(id.PrivateKey(), a)
		if err != nil {
			t.Fatal(err)
		}
		hosts = append(hosts, h)
	}

	if err := mn.LinkAll(); err != nil {
		t.Error(err)
	}
	if err := mn.ConnectAllButSelf(); err != nil {
		t.Error(err)
	}
	return hosts
}

func TestJoinParty(t *testing.T) {
	ApplyDeadline = false
	hosts := setupHosts(t, 4)
	var pcs []PartyCoordinator
	var peers []string

	timeout := time.Second * 10
	for _, el := range hosts {
		pcs = append(pcs, *NewPartyCoordinator(el, timeout))
		peers = append(peers, el.ID().String())
	}

	defer func() {
		for _, el := range pcs {
			el.Stop()
		}
	}()

	msgID := conversion.RandStringBytesMask(64)

	wg := sync.WaitGroup{}
	testProtocolGroup1 := []string{"/p2p/tss/gg18", "/p2p/tss/gg20"}
	testProtocolGroup2 := []string{"/p2p/tss/gg20"}

	for idx, el := range pcs {
		wg.Add(1)
		go func(coordinator PartyCoordinator) {
			defer wg.Done()
			// we simulate different nodes join at different time
			time.Sleep(time.Second * time.Duration(rand.Int()%10))
			testProtos := testProtocolGroup1
			if idx > 2 {
				testProtos = testProtocolGroup2
			}
			joinPartyReq := messages.JoinPartyRequest{
				ID:        msgID,
				Protocols: testProtos,
			}
			onlinePeers, proto, err := coordinator.JoinPartyWithRetry(&joinPartyReq, peers)
			if err != nil {
				t.Error(err)
			}
			assert.Nil(t, err)
			assert.Len(t, onlinePeers, 4)
			assert.Equal(t, proto, protocol.ConvertFromStrings([]string{"/p2p/tss/gg20"})[0])
		}(el)
	}

	wg.Wait()
}

func TestJoinPartyTimeOut(t *testing.T) {
	ApplyDeadline = false
	timeout := time.Second
	hosts := setupHosts(t, 4)
	var pcs []*PartyCoordinator
	var peers []string
	for _, el := range hosts {
		pcs = append(pcs, NewPartyCoordinator(el, timeout))
	}
	sort.Slice(pcs, func(i, j int) bool {
		return pcs[i].host.ID().String() > pcs[j].host.ID().String()
	})
	for _, el := range pcs {
		peers = append(peers, el.host.ID().String())
	}

	defer func() {
		for _, el := range pcs {
			el.Stop()
		}
	}()

	msgID := conversion.RandStringBytesMask(64)

	joinPartyReq := messages.JoinPartyRequest{
		ID:        msgID,
		Protocols: []string{"/p2p/tss/gg18"},
	}
	wg := sync.WaitGroup{}

	for _, el := range pcs[:2] {
		wg.Add(1)
		go func(coordinator *PartyCoordinator) {
			defer wg.Done()
			onlinePeers, _, err := coordinator.JoinPartyWithRetry(&joinPartyReq, peers)
			assert.Errorf(t, err, errJoinPartyTimeout.Error())
			var onlinePeersStr []string
			for _, el := range onlinePeers {
				onlinePeersStr = append(onlinePeersStr, el.String())
			}
			sort.Strings(onlinePeersStr)
			expected := peers[:2]
			sort.Strings(expected)
			assert.EqualValues(t, onlinePeersStr, expected)
		}(el)
	}

	wg.Wait()
}

func TestJoinPartyUnsupportedProtocol(t *testing.T) {
	ApplyDeadline = false
	hosts := setupHosts(t, 4)
	var pcs []PartyCoordinator
	var peers []string

	timeout := time.Second * 10
	for _, el := range hosts {
		pcs = append(pcs, *NewPartyCoordinator(el, timeout))
		peers = append(peers, el.ID().String())
	}

	defer func() {
		for _, el := range pcs {
			el.Stop()
		}
	}()

	msgID := conversion.RandStringBytesMask(64)

	wg := sync.WaitGroup{}

	for _, el := range pcs {
		wg.Add(1)
		go func(coordinator PartyCoordinator) {
			defer wg.Done()
			joinPartyReq := messages.JoinPartyRequest{
				ID:        msgID,
				Protocols: []string{"/tss/invalidProtocol"},
			}
			_, _, err := coordinator.JoinPartyWithRetry(&joinPartyReq, peers)
			assert.Error(t, err, "unknown protocol")
		}(el)
	}

	wg.Wait()
}

func TestGetPeerIDs(t *testing.T) {
	ApplyDeadline = false
	id1 := tnet.RandIdentityOrFatal(t)
	mn := mocknet.New(context.Background())
	// add peers to mock net

	a1 := tnet.RandLocalTCPAddress()
	h1, err := mn.AddPeer(id1.PrivateKey(), a1)
	if err != nil {
		t.Fatal(err)
	}
	p1 := h1.ID()
	timeout := time.Second * 5
	pc := NewPartyCoordinator(h1, timeout)
	r, err := pc.getPeerIDs([]string{})
	assert.Nil(t, err)
	assert.Len(t, r, 0)
	input := []string{
		p1.String(),
	}
	r1, err := pc.getPeerIDs(input)
	assert.Nil(t, err)
	assert.Len(t, r1, 1)
	assert.Equal(t, r1[0], p1)
	input = append(input, "whatever")
	r2, err := pc.getPeerIDs(input)
	assert.NotNil(t, err)
	assert.Len(t, r2, 0)
}
