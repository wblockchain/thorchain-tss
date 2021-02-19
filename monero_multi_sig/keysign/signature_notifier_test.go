package keysign

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p-core/peer"
	tnet "github.com/libp2p/go-libp2p-testing/net"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
	"github.com/stretchr/testify/assert"
	moneroWallet "gitlab.com/thorchain/tss/monero-wallet-rpc/wallet"

	"gitlab.com/thorchain/tss/go-tss/conversion"
	"gitlab.com/thorchain/tss/go-tss/p2p"
)

func TestSignatureNotifierHappyPath(t *testing.T) {
	conversion.SetupBech32Prefix()
	p2p.ApplyDeadline = false
	id1 := tnet.RandIdentityOrFatal(t)
	id2 := tnet.RandIdentityOrFatal(t)
	id3 := tnet.RandIdentityOrFatal(t)
	mn := mocknet.New(context.Background())
	// add peers to mock net

	a1 := tnet.RandLocalTCPAddress()
	a2 := tnet.RandLocalTCPAddress()
	a3 := tnet.RandLocalTCPAddress()

	h1, err := mn.AddPeer(id1.PrivateKey(), a1)
	if err != nil {
		t.Fatal(err)
	}
	p1 := h1.ID()
	h2, err := mn.AddPeer(id2.PrivateKey(), a2)
	if err != nil {
		t.Fatal(err)
	}
	p2 := h2.ID()
	h3, err := mn.AddPeer(id3.PrivateKey(), a3)
	if err != nil {
		t.Fatal(err)
	}
	p3 := h3.ID()
	if err := mn.LinkAll(); err != nil {
		t.Error(err)
	}
	if err := mn.ConnectAllButSelf(); err != nil {
		t.Error(err)
	}
	n1 := NewSignatureNotifier(h1)
	n2 := NewSignatureNotifier(h2)
	n3 := NewSignatureNotifier(h3)
	assert.NotNil(t, n1)
	assert.NotNil(t, n2)
	assert.NotNil(t, n3)

	messageID := "testMessage"
	rpcAddress := fmt.Sprintf("http://%s:18083/json_rpc", remoteAddress[0])
	rpcWalletConfig := moneroWallet.Config{
		Address: rpcAddress,
	}
	wallet := moneroWallet.New(rpcWalletConfig)
	walletName := "thorpub1addwnpepq2m5ng0e6vm66feecrwxp37cdvmezsysghskz3t5w2du4c48qwupxn96nrr.mo"
	passcode := "f754b5c0b920f5ec3e364b1bf30947dd8a84eccc5cf14bd07a6fd227d0d36f25"
	// now open the wallet
	walletOpenReq := moneroWallet.RequestOpenWallet{
		Filename: walletName,
		Password: passcode,
	}
	err = wallet.OpenWallet(&walletOpenReq)
	assert.Nil(t, err)

	spendProof := MoneroSpendProof{
		TxKey:         "6283f00c65ddf91e3f28439f437abf983039284468fefaeaa16ecb6cd7492205",
		TransactionID: "549d0034f7799eecf7531d5311a3c8fee08eacc1fe964e791973a958d175b87a",
	}

	sigChan := make(chan string)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		sig, err := n1.WaitForSignature(messageID, testEncodedTransaction, wallet, time.Second*30, sigChan)
		assert.Nil(t, err)
		assert.NotNil(t, sig)
	}()
	assert.Nil(t, n2.BroadcastSignature(messageID, &spendProof, []peer.ID{
		p1, p3,
	}))
	assert.Nil(t, n3.BroadcastSignature(messageID, &spendProof, []peer.ID{
		p1, p2,
	}))
	wg.Wait()
}
