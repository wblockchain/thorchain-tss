package keyRegroup

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/binance-chain/tss-lib/crypto"
	btss "github.com/binance-chain/tss-lib/tss"
	"github.com/ipfs/go-log"
	p2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-peerstore/addr"
	tnet "github.com/libp2p/go-libp2p-testing/net"
	mocknet "github.com/libp2p/go-libp2p/p2p/net/mock"
	tcrypto "github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/secp256k1"

	btsskeygen "github.com/binance-chain/tss-lib/ecdsa/keygen"
	maddr "github.com/multiformats/go-multiaddr"
	. "gopkg.in/check.v1"

	"gitlab.com/thorchain/tss/go-tss/common"
	"gitlab.com/thorchain/tss/go-tss/conversion"
	"gitlab.com/thorchain/tss/go-tss/messages"
	"gitlab.com/thorchain/tss/go-tss/p2p"
	"gitlab.com/thorchain/tss/go-tss/storage"
)

var (
	testPubKeys = []string{
		"thorpub1addwnpepq2m5ng0e6vm66feecrwxp37cdvmezsysghskz3t5w2du4c48qwupxn96nrr",
		"thorpub1addwnpepqfjcw5l4ay5t00c32mmlky7qrppepxzdlkcwfs2fd5u73qrwna0vzag3y4j",
		"thorpub1addwnpepq2ryyje5zr09lq7gqptjwnxqsy2vcdngvwd6z7yt5yjcnyj8c8cn559xe69",
		"thorpub1addwnpepqtdklw8tf3anjz7nn5fly3uvq2e67w2apn560s4smmrt9e3x52nt2svmmu3",
		"thorpub1addwnpepqtspqyy6gk22u37ztra4hq3hdakc0w0k60sfy849mlml2vrpfr0wvm6uz09",
	}
	testPriKeyArr = []string{
		"91S1wLkg9ew+Nksb8wlH3YqE7Mxc8UvQem/SJ9DTbyU=",
		"6LABmWB4iXqkqOJ9H0YFEA2CSSx6bA7XAKGyI/TDtas=",
		"528pkgjuCWfHx1JihEjiIXS7jfTS/viEdAbjqVvSifQ=",
		"JFB2LIJZtK+KasK00NcNil4PRJS4c4liOnK0nDalhqc=",
		"vLMGhVXMOXQVnAE3BUU8fwNj/q0ZbndKkwmxfS5EN9Y=",
	}

	testNodePrivkey = []string{
		"Zjc1NGI1YzBiOTIwZjVlYzNlMzY0YjFiZjMwOTQ3ZGQ4YTg0ZWNjYzVjZjE0YmQwN2E2ZmQyMjdkMGQzNmYyNQ==",
		"ZThiMDAxOTk2MDc4ODk3YWE0YThlMjdkMWY0NjA1MTAwZDgyNDkyYzdhNmMwZWQ3MDBhMWIyMjNmNGMzYjVhYg==",
		"ZTc2ZjI5OTIwOGVlMDk2N2M3Yzc1MjYyODQ0OGUyMjE3NGJiOGRmNGQyZmVmODg0NzQwNmUzYTk1YmQyODlmNA==",
		"MjQ1MDc2MmM4MjU5YjRhZjhhNmFjMmI0ZDBkNzBkOGE1ZTBmNDQ5NGI4NzM4OTYyM2E3MmI0OWMzNmE1ODZhNw==",
		"YmNiMzA2ODU1NWNjMzk3NDE1OWMwMTM3MDU0NTNjN2YwMzYzZmVhZDE5NmU3NzRhOTMwOWIxN2QyZTQ0MzdkNg==",
	}

	targets = []string{
		"16Uiu2HAmACG5DtqmQsHtXg4G2sLS65ttv84e7MrL4kapkjfmhxAp", "16Uiu2HAm4TmEzUqy3q3Dv7HvdoSboHk5sFj2FH3npiN5vDbJC6gh",
		"16Uiu2HAm2FzqoUdS6Y9Esg2EaGcAG5rVe1r6BFNnmmQr2H3bqafa",
	}
)

const testPoolPubKey = "thorpub1addwnpepqv6xp3fmm47dfuzglywqvpv8fdjv55zxte4a26tslcezns5czv586u2fw33"

func TestPackage(t *testing.T) { TestingT(t) }

type TssKeyRegroupTestSuite struct {
	comms        []*p2p.Communication
	preParams    []*btsskeygen.LocalPreParams
	oldPartyNum  int
	newPartyNum  int
	stateMgrs    []storage.LocalStateManager
	nodePrivKeys []tcrypto.PrivKey
	targePeers   []peer.ID
	hosts        []host.Host
}

var _ = Suite(&TssKeyRegroupTestSuite{})

func (s *TssKeyRegroupTestSuite) SetUpSuite(c *C) {
	common.InitLog("info", true, "keygen_test")
	conversion.SetupBech32Prefix()
	p2p.ApplyDeadline = false
	s.oldPartyNum = 4
	s.newPartyNum = 1
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
		s.targePeers = append(s.targePeers, p)
	}

	s.hosts = s.setupTestNetwork(c, testPriKeyArr)
}

func (s *TssKeyRegroupTestSuite) TearDownSuite(c *C) {
	for i, _ := range s.comms {
		tempFilePath := path.Join(os.TempDir(), strconv.Itoa(i))
		err := os.RemoveAll(tempFilePath)
		c.Assert(err, IsNil)
	}
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

func (s *TssKeyRegroupTestSuite) setupTestNetwork(c *C, privkeys []string) []host.Host {
	mn := mocknet.New(context.Background())
	var hosts []host.Host
	for _, el := range privkeys {
		buf, err := base64.StdEncoding.DecodeString(el)
		c.Assert(err, IsNil)

		p2pPriKey, err := p2pcrypto.UnmarshalSecp256k1PrivateKey(buf)
		c.Assert(err, IsNil)
		a := tnet.RandLocalTCPAddress()
		h, err := mn.AddPeer(p2pPriKey, a)
		c.Assert(err, IsNil)
		hosts = append(hosts, h)
	}

	err := mn.LinkAll()
	c.Assert(err, IsNil)
	err = mn.ConnectAllButSelf()
	c.Assert(err, IsNil)
	return hosts
}

// SetUpTest set up environment for test key gen
func (s *TssKeyRegroupTestSuite) SetUpTest(c *C) {
	// since regroup p2p members are different from the reset of the tests, we need
	// to wait a little bit of time to allow other p2p networks tear down firstly.
	partyNum := s.oldPartyNum + s.newPartyNum
	s.comms = make([]*p2p.Communication, partyNum)
	s.stateMgrs = make([]storage.LocalStateManager, partyNum)
	s.preParams = getPreparams(c)
	for i := 0; i < len(s.hosts); i++ {
		comm, err := p2p.NewCommunication("asgard", []maddr.Multiaddr{}, 123, "")
		c.Assert(err, IsNil)
		h := s.hosts[i]
		h.SetStreamHandler(p2p.TSSProtocolID, comm.HandleStream)
		comm.SetHost(h)
		s.comms[i] = comm
		comm.StartProcessing()
	}

	baseHome := path.Join(os.TempDir(), strconv.Itoa(0))
	fMgr, err := storage.NewFileStateMgr(baseHome)
	c.Assert(err, IsNil)
	s.stateMgrs[0] = fMgr

	for i := 0; i < s.oldPartyNum; i++ {
		f := &MockLocalStateManager{
			file: fmt.Sprintf("../test_data/keysign_data/%d.json", i),
		}
		s.stateMgrs[i+1] = f
	}
}

func (s *TssKeyRegroupTestSuite) TearDownTest(c *C) {
	time.Sleep(time.Second)
	for _, item := range s.comms {
		c.Assert(item.Stop(), IsNil)
	}
}

func getPreparams(c *C) []*btsskeygen.LocalPreParams {
	const (
		testFileLocation = "../test_data"
		preParamTestFile = "preParam_test.data"
	)
	var preParamArray []*btsskeygen.LocalPreParams
	buf, err := ioutil.ReadFile(path.Join(testFileLocation, preParamTestFile))
	c.Assert(err, IsNil)
	preParamsStr := strings.Split(string(buf), "\n")
	for _, item := range preParamsStr {
		var preParam btsskeygen.LocalPreParams
		val, err := hex.DecodeString(item)
		c.Assert(err, IsNil)
		c.Assert(json.Unmarshal(val, &preParam), IsNil)
		preParamArray = append(preParamArray, &preParam)
	}
	return preParamArray
}

func (s *TssKeyRegroupTestSuite) TestKeyRegroup(c *C) {
	log.SetLogLevel("tss-lib", "info")
	sort.Strings(testPubKeys)
	req := NewRequest(testPoolPubKey, testPubKeys[1:5], testPubKeys[0:4], 10, "")

	messageID, err := common.MsgToHashString([]byte(strings.Join(req.NewPartyKeys, "")))
	c.Assert(err, IsNil)
	conf := common.TssConfig{
		KeyGenTimeout:     120 * time.Second,
		KeySignTimeout:    120 * time.Second,
		KeyRegroupTimeout: 120 * time.Second,
		PreParamTimeout:   5 * time.Second,
	}
	wg := sync.WaitGroup{}
	lock := &sync.Mutex{}
	keyRegroupResult := make(map[int]*crypto.ECPoint)
	for i := 0; i < (s.oldPartyNum + s.newPartyNum); i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			comm := s.comms[idx]
			stopChan := make(chan struct{})
			localPubKey := testPubKeys[idx]
			keygenInstance := NewTssKeyReGroup(
				comm.GetLocalPeerID(),
				conf,
				localPubKey,
				comm.BroadcastMsgChan,
				stopChan,
				s.preParams[idx],
				messageID,
				s.stateMgrs[idx], s.nodePrivKeys[idx], s.comms[idx])
			c.Assert(keygenInstance, NotNil)
			keygenMsgChannel := keygenInstance.GetTssKeyGenChannels()
			comm.SetSubscribe(messages.TSSPartyReGroup, messageID, keygenMsgChannel)
			comm.SetSubscribe(messages.TSSPartReGroupVerMSg, messageID, keygenMsgChannel)
			comm.SetSubscribe(messages.TSSControlMsg, messageID, keygenMsgChannel)
			comm.SetSubscribe(messages.TSSTaskDone, messageID, keygenMsgChannel)
			defer comm.CancelSubscribe(messages.TSSPartyReGroup, messageID)
			defer comm.CancelSubscribe(messages.TSSPartReGroupVerMSg, messageID)
			defer comm.CancelSubscribe(messages.TSSControlMsg, messageID)
			defer comm.CancelSubscribe(messages.TSSTaskDone, messageID)

			if idx == 0 {
				// saveData := btsskeygen.NewLocalPartySaveData(4)
				var saveData btsskeygen.LocalPartySaveData
				saveData.LocalPreParams = *s.preParams[5]
				resp, err := keygenInstance.GenerateNewKey(req, saveData)
				c.Assert(err, IsNil)
				if resp != nil {
					lock.Lock()
					defer lock.Unlock()
					keyRegroupResult[idx] = resp
				}
			} else {
				localState, err := s.stateMgrs[idx].GetLocalState(req.PoolPubKey)
				c.Assert(err, IsNil)
				resp, err := keygenInstance.GenerateNewKey(req, localState.LocalData)
				c.Assert(err, IsNil)
				if resp != nil {
					lock.Lock()
					defer lock.Unlock()
					keyRegroupResult[idx] = resp
				}
			}
		}(i)
	}
	wg.Wait()
	c.Assert(keyRegroupResult, HasLen, 4)
	// we check whether the public key is the same before resharing
	data, err := s.stateMgrs[1].GetLocalState(testPoolPubKey)
	c.Assert(err, IsNil)
	for _, el := range keyRegroupResult {
		data.LocalData.ECDSAPub.Equals(el)
	}
}

func (s *TssKeyRegroupTestSuite) TestGenerateNewKeyWithStop(c *C) {
	c.Skip("we do not support blame right now")
	log.SetLogLevel("tss-lib", "debug")
	conf := common.TssConfig{
		KeyGenTimeout:     20 * time.Second,
		KeySignTimeout:    20 * time.Second,
		KeyRegroupTimeout: 20 * time.Second,
		PreParamTimeout:   5 * time.Second,
	}
	wg := sync.WaitGroup{}

	sort.Strings(testPubKeys)
	req := NewRequest(testPoolPubKey, testPubKeys[1:5], testPubKeys[0:4], 10, "")
	messageID, err := common.MsgToHashString([]byte(strings.Join(req.NewPartyKeys, "")))
	c.Assert(err, IsNil)
	for i := 0; i < (s.oldPartyNum + s.newPartyNum); i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			var localpubKey []string
			localpubKey = append(localpubKey, testPubKeys...)

			comm := s.comms[idx]
			stopChan := make(chan struct{})
			localPubKey := testPubKeys[idx]

			keygenInstance := NewTssKeyReGroup(
				comm.GetLocalPeerID(),
				conf,
				localPubKey,
				comm.BroadcastMsgChan,
				stopChan,
				s.preParams[idx],
				messageID,
				s.stateMgrs[idx], s.nodePrivKeys[idx], s.comms[idx])

			c.Assert(keygenInstance, NotNil)
			keygenMsgChannel := keygenInstance.GetTssKeyGenChannels()
			comm.SetSubscribe(messages.TSSKeyGenMsg, messageID, keygenMsgChannel)
			comm.SetSubscribe(messages.TSSKeyGenVerMsg, messageID, keygenMsgChannel)
			comm.SetSubscribe(messages.TSSControlMsg, messageID, keygenMsgChannel)
			comm.SetSubscribe(messages.TSSTaskDone, messageID, keygenMsgChannel)
			defer comm.CancelSubscribe(messages.TSSKeyGenMsg, messageID)
			defer comm.CancelSubscribe(messages.TSSKeyGenVerMsg, messageID)
			defer comm.CancelSubscribe(messages.TSSControlMsg, messageID)
			defer comm.CancelSubscribe(messages.TSSTaskDone, messageID)
			if idx == 2 {
				go func() {
					time.Sleep(time.Millisecond * 2000)
					close(keygenInstance.stopChan)
				}()
			}

			if idx == 0 {
				saveData := btsskeygen.NewLocalPartySaveData(4)
				_, err := keygenInstance.GenerateNewKey(req, saveData)
				c.Assert(err, NotNil)

			} else {
				localState, err := s.stateMgrs[idx].GetLocalState(req.PoolPubKey)
				c.Assert(err, IsNil)
				_, err = keygenInstance.GenerateNewKey(req, localState.LocalData)
				c.Assert(err, NotNil)

			}

			// we skip the node 1 as we force it to stop
			if idx != 0 {
				blames := keygenInstance.GetTssCommonStruct().GetBlameMgr().GetBlame().BlameNodes
				fmt.Printf(">>>>>>>.%v\n", blames)
				// c.Assert(blames, HasLen, 1)
				// c.Assert(blames[0].Pubkey, Equals, testPubKeys[0])
			}
		}(i)
	}
	wg.Wait()
}

func (s *TssKeyRegroupTestSuite) TestKeyRegroupWithError(c *C) {
	req := NewRequest(testPoolPubKey, testPubKeys[1:5], testPubKeys[0:4], 10, "")
	conf := common.TssConfig{}
	stateManager := &storage.MockLocalStateManager{}
	keyGenInstance := NewTssKeyReGroup("", conf, "", nil, nil, nil, "test", stateManager, s.nodePrivKeys[0], nil)
	saveData := btsskeygen.NewLocalPartySaveData(4)
	generatedKey, err := keyGenInstance.GenerateNewKey(req, saveData)
	c.Assert(err, NotNil)
	c.Assert(generatedKey, IsNil)
}

func (s *TssKeyRegroupTestSuite) TestCloseKeyGenNotifyChannel(c *C) {
	conf := common.TssConfig{}
	stateManager := &storage.MockLocalStateManager{}

	// req := NewRequest(testPubKeys[1:5], testPubKeys[0:4], 10, "")
	keyGenInstance := NewTssKeyReGroup("", conf, "", nil, nil, nil, "test", stateManager, s.nodePrivKeys[0], s.comms[0])

	taskDone := messages.TssTaskNotifier{TaskDone: true}
	taskDoneBytes, err := json.Marshal(taskDone)
	c.Assert(err, IsNil)

	msg := &messages.WrappedMessage{
		MessageType: messages.TSSTaskDone,
		MsgID:       "test",
		Payload:     taskDoneBytes,
	}
	partyIdMap := make(map[string]*btss.PartyID)
	partyIdMap["1"] = nil
	partyIdMap["2"] = nil
	fakePartyInfo := &common.PartyInfo{
		PartyMap:   nil,
		PartyIDMap: partyIdMap,
	}
	keyGenInstance.tssCommonStruct.SetPartyInfo(fakePartyInfo)
	err = keyGenInstance.tssCommonStruct.ProcessOneMessage(msg, "node1")
	c.Assert(err, IsNil)
	err = keyGenInstance.tssCommonStruct.ProcessOneMessage(msg, "node2")
	c.Assert(err, IsNil)
	err = keyGenInstance.tssCommonStruct.ProcessOneMessage(msg, "node1")
	c.Assert(err, ErrorMatches, "duplicated notification from peer node1 ignored")
}
