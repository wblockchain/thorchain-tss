package keysign

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p-peerstore/addr"
	"github.com/rs/zerolog/log"
	"gitlab.com/thorchain/tss/monero-wallet-rpc/wallet"

	"gitlab.com/thorchain/tss/go-tss/conversion"

	"github.com/libp2p/go-libp2p-core/peer"
	maddr "github.com/multiformats/go-multiaddr"
	tcrypto "github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/secp256k1"
	. "gopkg.in/check.v1"

	"gitlab.com/thorchain/tss/go-tss/common"
	"gitlab.com/thorchain/tss/go-tss/messages"
	"gitlab.com/thorchain/tss/go-tss/p2p"
	"gitlab.com/thorchain/tss/go-tss/storage"
)

const destWallet = "48Qp1DYY95wF2BNbhQZDd5J8dZCucMRz99Y4wAUaDjQhjX8royowfog1sN9WAdVeshQuvU6qKFi9Ji4gj9ZREkjTFYsQbZX"

var (
	testPubKeys = []string{
		"thorpub1addwnpepq2m5ng0e6vm66feecrwxp37cdvmezsysghskz3t5w2du4c48qwupxn96nrr",
		"thorpub1addwnpepq2ryyje5zr09lq7gqptjwnxqsy2vcdngvwd6z7yt5yjcnyj8c8cn559xe69",
		"thorpub1addwnpepqfey5l8v7azq0r4jlkd9hqqu8md0ff3vmtw2s6453zuzy8uf29fz54r7sr0",
		"thorpub1addwnpepqfjcw5l4ay5t00c32mmlky7qrppepxzdlkcwfs2fd5u73qrwna0vzag3y4j",
		"thorpub1addwnpepqtdklw8tf3anjz7nn5fly3uvq2e67w2apn560s4smmrt9e3x52nt2svmmu3",
		"thorpub1addwnpepqtspqyy6gk22u37ztra4hq3hdakc0w0k60sfy849mlml2vrpfr0wvm6uz09",
	}
	testPriKeyArr = []string{
		"91S1wLkg9ew+Nksb8wlH3YqE7Mxc8UvQem/SJ9DTbyU=",
		"6LABmWB4iXqkqOJ9H0YFEA2CSSx6bA7XAKGyI/TDtas=",
		"wm1XwwLAJNzMykWE98go8YOL4rBPBXz+JLBFDPSq5Ok=",
		"528pkgjuCWfHx1JihEjiIXS7jfTS/viEdAbjqVvSifQ=",
		"JFB2LIJZtK+KasK00NcNil4PRJS4c4liOnK0nDalhqc=",
		"vLMGhVXMOXQVnAE3BUU8fwNj/q0ZbndKkwmxfS5EN9Y=",
	}

	testNodePrivkey = []string{
		"Zjc1NGI1YzBiOTIwZjVlYzNlMzY0YjFiZjMwOTQ3ZGQ4YTg0ZWNjYzVjZjE0YmQwN2E2ZmQyMjdkMGQzNmYyNQ==",
		"ZThiMDAxOTk2MDc4ODk3YWE0YThlMjdkMWY0NjA1MTAwZDgyNDkyYzdhNmMwZWQ3MDBhMWIyMjNmNGMzYjVhYg==",
		"YzI2ZDU3YzMwMmMwMjRkY2NjY2E0NTg0ZjdjODI4ZjE4MzhiZTJiMDRmMDU3Y2ZlMjRiMDQ1MGNmNGFhZTRlOQ==",
		"ZTc2ZjI5OTIwOGVlMDk2N2M3Yzc1MjYyODQ0OGUyMjE3NGJiOGRmNGQyZmVmODg0NzQwNmUzYTk1YmQyODlmNA==",
		"MjQ1MDc2MmM4MjU5YjRhZjhhNmFjMmI0ZDBkNzBkOGE1ZTBmNDQ5NGI4NzM4OTYyM2E3MmI0OWMzNmE1ODZhNw==",
		"YmNiMzA2ODU1NWNjMzk3NDE1OWMwMTM3MDU0NTNjN2YwMzYzZmVhZDE5NmU3NzRhOTMwOWIxN2QyZTQ0MzdkNg==",
	}

	targets = []string{
		"16Uiu2HAmACG5DtqmQsHtXg4G2sLS65ttv84e7MrL4kapkjfmhxAp", "16Uiu2HAm4TmEzUqy3q3Dv7HvdoSboHk5sFj2FH3npiN5vDbJC6gh",
		"16Uiu2HAm2FzqoUdS6Y9Esg2EaGcAG5rVe1r6BFNnmmQr2H3bqafa",
	}
)

func TestPackage(t *testing.T) {
	TestingT(t)
}

type MockLocalStateManager struct {
	file string
}

func (m *MockLocalStateManager) SaveLocalState(state storage.KeygenLocalState) error {
	return nil
}

func (m *MockLocalStateManager) GetLocalState(pubKey string) (storage.KeygenLocalState, error) {
	buf, err := ioutil.ReadFile(m.file)
	if err != nil {
		return storage.KeygenLocalState{}, err
	}
	var state storage.KeygenLocalState
	if err := json.Unmarshal(buf, &state); err != nil {
		return storage.KeygenLocalState{}, err
	}
	return state, nil
}

func (s *MockLocalStateManager) SaveAddressBook(address map[peer.ID]addr.AddrList) error {
	return nil
}

func (s *MockLocalStateManager) RetrieveP2PAddresses() (addr.AddrList, error) {
	return nil, os.ErrNotExist
}

type TssKeysignTestSuite struct {
	comms        []*p2p.Communication
	partyNum     int
	stateMgrs    []storage.LocalStateManager
	nodePrivKeys []tcrypto.PrivKey
	targetPeers  []peer.ID
}

var _ = Suite(&TssKeysignTestSuite{})

func (s *TssKeysignTestSuite) SetUpSuite(c *C) {
	conversion.SetupBech32Prefix()
	common.InitLog("info", true, "keysign_test")

	for _, el := range testNodePrivkey {
		priHexBytes, err := base64.StdEncoding.DecodeString(el)
		c.Assert(err, IsNil)
		rawBytes, err := hex.DecodeString(string(priHexBytes))
		c.Assert(err, IsNil)
		var priKey secp256k1.PrivKey
		priKey = rawBytes[:32]
		s.nodePrivKeys = append(s.nodePrivKeys, priKey)
	}

	for _, el := range targets {
		p, err := peer.Decode(el)
		c.Assert(err, IsNil)
		s.targetPeers = append(s.targetPeers, p)
	}
}

func (s *TssKeysignTestSuite) SetUpTest(c *C) {
	if testing.Short() {
		c.Skip("skip the test")
		return
	}
	ports := []int{
		18666, 18667, 18668, 18669, 18670, 18671,
	}
	s.partyNum = 4
	s.comms = make([]*p2p.Communication, s.partyNum)
	s.stateMgrs = make([]storage.LocalStateManager, s.partyNum)
	bootstrapPeer := "/ip4/127.0.0.1/tcp/18666/p2p/16Uiu2HAm7m9i8A7cPENuL97sa5b6Xq7TSDNF6gGrSBhN41jWCmop"
	multiAddr, err := maddr.NewMultiaddr(bootstrapPeer)
	c.Assert(err, IsNil)
	for i := 0; i < s.partyNum; i++ {
		buf, err := base64.StdEncoding.DecodeString(testPriKeyArr[i])
		c.Assert(err, IsNil)
		if i == 0 {
			comm, err := p2p.NewCommunication("asgard", nil, ports[i], "")
			c.Assert(err, IsNil)
			c.Assert(comm.Start(buf), IsNil)
			s.comms[i] = comm
			continue
		}
		comm, err := p2p.NewCommunication("asgard", []maddr.Multiaddr{multiAddr}, ports[i], "")
		c.Assert(err, IsNil)
		c.Assert(comm.Start(buf), IsNil)
		s.comms[i] = comm
	}

	for i := 0; i < s.partyNum; i++ {
		f := &MockLocalStateManager{
			file: fmt.Sprintf("../test_data/keysign_data/%d.json", i),
		}
		s.stateMgrs[i] = f
	}
}

func (s *TssKeysignTestSuite) TestSignMessage(c *C) {
	if testing.Short() {
		c.Skip("skip the test")
		return
	}
	sort.Strings(testPubKeys)

	dst := wallet.Destination{
		Amount:  500,
		Address: "48Qp1DYY95wF2BNbhQZDd5J8dZCucMRz99Y4wAUaDjQhjX8royowfog1sN9WAdVeshQuvU6qKFi9Ji4gj9ZREkjTFYsQbZX",
	}

	t := wallet.RequestTransfer{
		Destinations:  []*wallet.Destination{&dst},
		GetTxHex:      true,
		RingSize:      11,
		GetTxKey:      true,
		GetTxMetadata: true,
	}

	tx, err := json.Marshal(t)
	c.Assert(err, IsNil)
	encodedTx := base64.StdEncoding.EncodeToString(tx)
	var reqs []Request
	remoteAddress := []string{"188.166.183.111", "178.128.155.101", "188.166.158.53", "104.236.7.106", "104.248.200.163", "139.59.237.127"}
	for i := 0; i < s.partyNum; i++ {
		var rpcaddress string
		rpcaddress = fmt.Sprintf("http://%s:18083/json_rpc", remoteAddress[i])
		req := NewRequest(10, testPubKeys[:4], "0.16.0", rpcaddress, encodedTx)
		reqs = append(reqs, req)
	}

	messageID, err := common.MsgToHashString([]byte(reqs[0].EncodedTx))
	c.Assert(err, IsNil)
	wg := sync.WaitGroup{}
	conf := common.TssConfig{
		KeyGenTimeout:   90 * time.Second,
		KeySignTimeout:  90 * time.Second,
		PreParamTimeout: 5 * time.Second,
	}

	for i := 0; i < s.partyNum; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			comm := s.comms[idx]
			stopChan := make(chan struct{})
			keysignIns, walletClient, err := NewMoneroKeySign(comm.GetLocalPeerID(),
				conf,
				comm.BroadcastMsgChan,
				stopChan, messageID,
				s.nodePrivKeys[idx], s.comms[idx], reqs[idx].RpcAddress)
			c.Assert(err, IsNil)

			defer func() {
				err := walletClient.CloseWallet()
				c.Assert(err, IsNil)
			}()
			keysignMsgChannel := keysignIns.GetTssKeySignChannels()

			comm.SetSubscribe(messages.TSSKeySignMsg, messageID, keysignMsgChannel)
			comm.SetSubscribe(messages.TSSKeySignVerMsg, messageID, keysignMsgChannel)
			comm.SetSubscribe(messages.TSSControlMsg, messageID, keysignMsgChannel)
			comm.SetSubscribe(messages.TSSTaskDone, messageID, keysignMsgChannel)
			defer comm.CancelSubscribe(messages.TSSKeySignMsg, messageID)
			defer comm.CancelSubscribe(messages.TSSKeySignVerMsg, messageID)
			defer comm.CancelSubscribe(messages.TSSControlMsg, messageID)
			defer comm.CancelSubscribe(messages.TSSTaskDone, messageID)
			signedTx, err := keysignIns.SignMessage(reqs[idx].EncodedTx, reqs[idx].SignerPubKeys)
			c.Assert(err, IsNil)
			if signedTx != nil {
				checkRequest := wallet.RequestCheckTxProof{
					TxID:      signedTx.TransactionID,
					Signature: signedTx.SignatureProof,
					Address:   destWallet,
				}
				log.Printf("-------->signedTx%v:%v\n", signedTx.SignatureProof, signedTx.SignatureProof)
				respCheck, err := keysignIns.walletClient.CheckTxProof(&checkRequest)
				c.Assert(err, IsNil)
				c.Assert(respCheck.Good, Equals, true)
			}
		}(i)
	}
	wg.Wait()
}
