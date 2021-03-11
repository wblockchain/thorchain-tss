package keysign

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p-peerstore/addr"
	"github.com/rs/zerolog/log"
	"gitlab.com/thorchain/tss/monero-wallet-rpc/wallet"

	"github.com/libp2p/go-libp2p-core/peer"
	maddr "github.com/multiformats/go-multiaddr"
	tcrypto "github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/secp256k1"
	. "gopkg.in/check.v1"

	"gitlab.com/thorchain/tss/go-tss/conversion"

	"gitlab.com/thorchain/tss/go-tss/common"
	"gitlab.com/thorchain/tss/go-tss/messages"
	"gitlab.com/thorchain/tss/go-tss/p2p"
	"gitlab.com/thorchain/tss/go-tss/storage"
)

const (
	destWallet      = "48Qp1DYY95wF2BNbhQZDd5J8dZCucMRz99Y4wAUaDjQhjX8royowfog1sN9WAdVeshQuvU6qKFi9Ji4gj9ZREkjTFYsQbZX"
	testPoolAddress = "4AeYvCc9ZsvHBy2r52wR4pg2yzgvMCrQ1dAKu6vAb5yCR4e6aGsBtNT3J31eXnqGsGbe8pgRcebm1LiLLx7owWk1R4QVwMg"
)

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
	// you have to setup the wallet before you run this test, change the IP as needed
	remoteAddress = []string{"134.209.108.57", "167.99.11.83", "46.101.91.4", "134.209.35.249", "174.138.10.57", "134.209.101.44"}
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
	EnableTest = true
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
	for i := 0; i < s.partyNum; i++ {
		var rpcaddress string
		rpcaddress = fmt.Sprintf("http://%s:18083/json_rpc", remoteAddress[i])
		req := NewRequest(10, testPubKeys[:4], "0.16.0", rpcaddress, testPoolAddress, encodedTx)
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
				s.nodePrivKeys[idx], s.comms[idx], reqs[idx].RpcAddress, reqs[idx].PoolAddress)
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
				checkRequest := wallet.RequestCheckTxKey{
					TxID:    signedTx.TransactionID,
					TxKey:   signedTx.TxKey,
					Address: destWallet,
				}

				counter := 0
				var respCheck *wallet.ResponseCheckTxKey
				var err error
				for ; counter < 10; counter++ {
					respCheck, err = keysignIns.walletClient.CheckTxKey(&checkRequest)
					if err == nil {
						break
					}
					time.Sleep(time.Second * 2)

				}
				if counter >= 10 {
					c.Assert(err, IsNil)
					c.Fatal("fail to check the tx with the tx key")
				}
				c.Assert(respCheck.Received, Equals, uint64(500))
				log.Info().Msgf("check result %v,%v,%v\n", respCheck.Confirmations, respCheck.InPool, respCheck.Received)
			}
		}(i)
	}
	wg.Wait()
}

func (s *TssKeysignTestSuite) TestSignMessageCheckFailure(c *C) {
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

	dst2 := wallet.Destination{
		Amount:  510,
		Address: "48Qp1DYY95wF2BNbhQZDd5J8dZCucMRz99Y4wAUaDjQhjX8royowfog1sN9WAdVeshQuvU6qKFi9Ji4gj9ZREkjTFYsQbZX",
	}

	t2 := wallet.RequestTransfer{
		Destinations:  []*wallet.Destination{&dst2},
		GetTxHex:      true,
		RingSize:      11,
		GetTxKey:      true,
		GetTxMetadata: true,
	}

	tx2, err := json.Marshal(t2)
	c.Assert(err, IsNil)
	encodedTx2 := base64.StdEncoding.EncodeToString(tx2)
	_ = encodedTx2
	var reqs []Request
	for i := 0; i < s.partyNum; i++ {
		var rpcaddress string
		rpcaddress = fmt.Sprintf("http://%s:18083/json_rpc", remoteAddress[i])
		var req Request
		if i == 1 {
			req = NewRequest(10, testPubKeys[:4], "0.16.0", rpcaddress, testPoolAddress, encodedTx2)
		} else {
			req = NewRequest(10, testPubKeys[:4], "0.16.0", rpcaddress, testPoolAddress, encodedTx)
		}
		reqs = append(reqs, req)
	}

	messageID, err := common.MsgToHashString([]byte(reqs[0].EncodedTx))
	c.Assert(err, IsNil)
	wg := sync.WaitGroup{}
	conf := common.TssConfig{
		KeyGenTimeout:   40 * time.Second,
		KeySignTimeout:  40 * time.Second,
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
				s.nodePrivKeys[idx], s.comms[idx], reqs[idx].RpcAddress, reqs[idx].PoolAddress)
			c.Assert(err, IsNil)

			defer func() {
				err := walletClient.CloseWallet()
				c.Assert(err, IsNil)
				time.Sleep(time.Second * 5)
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
			_, err = keysignIns.SignMessage(reqs[idx].EncodedTx, reqs[idx].SignerPubKeys)
			blameMgr := keysignIns.moneroCommonStruct.GetBlameMgr()
			nodes := blameMgr.GetBlame().BlameNodes
			if idx != 1 {
				c.Assert(err, NotNil)
				c.Assert(nodes[0].Pubkey, Equals, "thorpub1addwnpepq2ryyje5zr09lq7gqptjwnxqsy2vcdngvwd6z7yt5yjcnyj8c8cn559xe69")
				c.Assert(nodes, HasLen, 1)
			}
		}(i)
	}
	wg.Wait()
}

func (s *TssKeysignTestSuite) TearDownSuite(c *C) {
	for i, _ := range s.comms {
		tempFilePath := path.Join(os.TempDir(), strconv.Itoa(i))
		err := os.RemoveAll(tempFilePath)
		c.Assert(err, IsNil)
	}
}

func (s *TssKeysignTestSuite) TearDownTest(c *C) {
	if testing.Short() {
		c.Skip("skip the test")
		return
	}
	time.Sleep(time.Second)
	for _, item := range s.comms {
		c.Assert(item.Stop(), IsNil)
	}
	time.Sleep(time.Second * 5)
}
