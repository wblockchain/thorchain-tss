package keygen

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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p-core/peer"
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

	remoteAddress = []string{"188.166.183.111", "178.128.155.101", "188.166.158.53", "104.236.7.106", "104.248.200.163", "139.59.237.127"}
)

func TestPackage(t *testing.T) { TestingT(t) }

type TssKeygenTestSuite struct {
	comms        []*p2p.Communication
	preParams    []*btsskeygen.LocalPreParams
	partyNum     int
	stateMgrs    []storage.LocalStateManager
	nodePrivKeys []tcrypto.PrivKey
	targePeers   []peer.ID
}

var _ = Suite(&TssKeygenTestSuite{})

func (s *TssKeygenTestSuite) SetUpSuite(c *C) {
	common.InitLog("info", true, "keygen_test")
	conversion.SetupBech32Prefix()
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
}

func (s *TssKeygenTestSuite) TearDownSuite(c *C) {
	for i, _ := range s.comms {
		tempFilePath := path.Join(os.TempDir(), strconv.Itoa(i))
		err := os.RemoveAll(tempFilePath)
		c.Assert(err, IsNil)
	}
}

// SetUpTest set up environment for test key gen
func (s *TssKeygenTestSuite) SetUpTest(c *C) {
	ports := []int{
		18666, 18667, 18668, 18669, 18670, 18671,
	}
	s.partyNum = 6
	s.comms = make([]*p2p.Communication, s.partyNum)
	s.stateMgrs = make([]storage.LocalStateManager, s.partyNum)
	bootstrapPeer := "/ip4/127.0.0.1/tcp/18666/p2p/16Uiu2HAm7m9i8A7cPENuL97sa5b6Xq7TSDNF6gGrSBhN41jWCmop"
	multiAddr, err := maddr.NewMultiaddr(bootstrapPeer)
	c.Assert(err, IsNil)
	s.preParams = getPreparams(c)
	for i := 0; i < s.partyNum; i++ {
		buf, err := base64.StdEncoding.DecodeString(testPriKeyArr[i])
		c.Assert(err, IsNil)
		if i == 0 {
			comm, err := p2p.NewCommunication("asgard", nil, ports[i], "")
			c.Assert(err, IsNil)
			c.Assert(comm.Start(buf[:]), IsNil)
			s.comms[i] = comm
			continue
		}
		comm, err := p2p.NewCommunication("asgard", []maddr.Multiaddr{multiAddr}, ports[i], "")
		c.Assert(err, IsNil)
		c.Assert(comm.Start(buf[:]), IsNil)
		s.comms[i] = comm
	}

	for i := 0; i < s.partyNum; i++ {
		baseHome := path.Join(os.TempDir(), strconv.Itoa(i))
		fMgr, err := storage.NewFileStateMgr(baseHome)
		c.Assert(err, IsNil)
		s.stateMgrs[i] = fMgr
	}
}

func (s *TssKeygenTestSuite) TearDownTest(c *C) {
	time.Sleep(time.Second)
	for _, item := range s.comms {
		c.Assert(item.Stop(), IsNil)
	}
}

func getPreparams(c *C) []*btsskeygen.LocalPreParams {
	const (
		testFileLocation = "../../test_data"
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

func (s *TssKeygenTestSuite) TestGenerateNewKey(c *C) {
	set := os.Getenv("SKIPGEN")
	if set != "" {
		c.Log("we skip the keygen test")
		c.Skip("not suitable for testing")
	}
	sort.Strings(testPubKeys)
	var reqs []Request

	for i := 0; i < s.partyNum; i++ {
		var rpcaddress string
		rpcaddress = fmt.Sprintf("http://%s:18083/json_rpc", remoteAddress[i])
		req := NewRequest(testPubKeys, 10, "", rpcaddress)
		reqs = append(reqs, req)
	}

	messageID, err := common.MsgToHashString([]byte(strings.Join(reqs[0].Keys, "")))
	c.Assert(err, IsNil)
	conf := common.TssConfig{
		KeyGenTimeout:   60 * time.Second,
		KeySignTimeout:  60 * time.Second,
		PreParamTimeout: 5 * time.Second,
	}
	wg := sync.WaitGroup{}
	lock := &sync.Mutex{}
	keygenResult := make(map[int]string)
	for i := 0; i < s.partyNum; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			comm := s.comms[idx]
			stopChan := make(chan struct{})
			localPubKey := testPubKeys[idx]
			keygenInstance := NewMoneroKeyGen(
				comm.GetLocalPeerID(),
				conf,
				localPubKey,
				comm.BroadcastMsgChan,
				stopChan,
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
			resp, _, err := keygenInstance.GenerateNewKey(reqs[idx])
			c.Assert(err, IsNil)
			lock.Lock()
			defer lock.Unlock()
			keygenResult[idx] = resp
		}(i)
	}
	wg.Wait()
	ans := keygenResult[0]
	for _, el := range keygenResult {
		c.Assert(ans, Equals, el)
	}
}

//func (s *TssKeygenTestSuite) TestGenerateNewKeyWithStop(c *C) {
//	sort.Strings(testPubKeys)
//	req := NewRequest(testPubKeys, 10, "")
//	messageID, err := common.MsgToHashString([]byte(strings.Join(req.Keys, "")))
//	c.Assert(err, IsNil)
//	conf := common.TssConfig{
//		KeyGenTimeout:   10 * time.Second,
//		KeySignTimeout:  10 * time.Second,
//		PreParamTimeout: 5 * time.Second,
//	}
//	wg := sync.WaitGroup{}
//
//	for i := 0; i < s.partyNum; i++ {
//		wg.Add(1)
//		go func(idx int) {
//			defer wg.Done()
//			comm := s.comms[idx]
//			stopChan := make(chan struct{})
//			localPubKey := testPubKeys[idx]
//			keygenInstance := NewMoneroKeyGen(
//				comm.GetLocalPeerID(),
//				conf,
//				localPubKey,
//				comm.BroadcastMsgChan,
//				stopChan,
//				s.preParams[idx],
//				messageID,
//				s.stateMgrs[idx],
//				s.nodePrivKeys[idx], s.comms[idx])
//			c.Assert(keygenInstance, NotNil)
//			keygenMsgChannel := keygenInstance.GetTssKeyGenChannels()
//			comm.SetSubscribe(messages.TSSKeyGenMsg, messageID, keygenMsgChannel)
//			comm.SetSubscribe(messages.TSSKeyGenVerMsg, messageID, keygenMsgChannel)
//			comm.SetSubscribe(messages.TSSControlMsg, messageID, keygenMsgChannel)
//			comm.SetSubscribe(messages.TSSTaskDone, messageID, keygenMsgChannel)
//			defer comm.CancelSubscribe(messages.TSSKeyGenMsg, messageID)
//			defer comm.CancelSubscribe(messages.TSSKeyGenVerMsg, messageID)
//			defer comm.CancelSubscribe(messages.TSSControlMsg, messageID)
//			defer comm.CancelSubscribe(messages.TSSTaskDone, messageID)
//			if idx == 1 {
//				go func() {
//					time.Sleep(time.Millisecond * 200)
//					close(keygenInstance.stopChan)
//				}()
//			}
//			_, err := keygenInstance.GenerateNewKey(req)
//			c.Assert(err, NotNil)
//			// we skip the node 1 as we force it to stop
//			if idx != 1 {
//				blames := keygenInstance.GetMoneroCommonStruct().GetBlameMgr().GetBlame().BlameNodes
//				c.Assert(blames, HasLen, 1)
//				c.Assert(blames[0].Pubkey, Equals, testPubKeys[1])
//			}
//		}(i)
//	}
//	wg.Wait()
//}
//
//func (s *TssKeygenTestSuite) TestKeyGenWithError(c *C) {
//	req := Request{
//		Keys: testPubKeys[:],
//	}
//	conf := common.TssConfig{}
//	stateManager := &storage.MockLocalStateManager{}
//	keyGenInstance := NewMoneroKeyGen("", conf, "", nil, nil, nil, "test", stateManager, s.nodePrivKeys[0], nil)
//	generatedKey, err := keyGenInstance.GenerateNewKey(req)
//	c.Assert(err, NotNil)
//	c.Assert(generatedKey, IsNil)
//}
//
//func (s *TssKeygenTestSuite) TestCloseKeyGennotifyChannel(c *C) {
//	conf := common.TssConfig{}
//	stateManager := &storage.MockLocalStateManager{}
//	keyGenInstance := NewMoneroKeyGen("", conf, "", nil, nil, nil, "test", stateManager, s.nodePrivKeys[0], s.comms[0])
//
//	taskDone := messages.TssTaskNotifier{TaskDone: true}
//	taskDoneBytes, err := json.Marshal(taskDone)
//	c.Assert(err, IsNil)
//
//	msg := &messages.WrappedMessage{
//		MessageType: messages.TSSTaskDone,
//		MsgID:       "test",
//		Payload:     taskDoneBytes,
//	}
//	partyIdMap := make(map[string]*btss.PartyID)
//	partyIdMap["1"] = nil
//	partyIdMap["2"] = nil
//	fakePartyInfo := &common.PartyInfo{
//		Party:      nil,
//		PartyIDMap: partyIdMap,
//	}
//	keyGenInstance.moneroCommonStruct.SetPartyInfo(fakePartyInfo)
//	err = keyGenInstance.moneroCommonStruct.ProcessOneMessage(msg, "node1", nil)
//	c.Assert(err, IsNil)
//	err = keyGenInstance.moneroCommonStruct.ProcessOneMessage(msg, "node2", nil)
//	c.Assert(err, IsNil)
//	err = keyGenInstance.moneroCommonStruct.ProcessOneMessage(msg, "node1", nil)
//	c.Assert(err, ErrorMatches, "duplicated notification from peer node1 ignored")
//}
