package keygen

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	bkg "github.com/binance-chain/tss-lib/ecdsa/keygen"
	btss "github.com/binance-chain/tss-lib/tss"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	tcrypto "github.com/tendermint/tendermint/crypto"

	moneroWallet "gitlab.com/thorchain/tss/monero-wallet-rpc/wallet"

	"gitlab.com/thorchain/tss/go-tss/common"
	"gitlab.com/thorchain/tss/go-tss/conversion"
	"gitlab.com/thorchain/tss/go-tss/messages"
	"gitlab.com/thorchain/tss/go-tss/monero_multi_sig"
	"gitlab.com/thorchain/tss/go-tss/p2p"
	"gitlab.com/thorchain/tss/go-tss/storage"
)

type MoneroKeyGen struct {
	logger             zerolog.Logger
	localNodePubKey    string
	preParams          *bkg.LocalPreParams
	moneroCommonStruct *common.TssCommon
	stopChan           chan struct{} // channel to indicate whether we should stop
	localParty         *btss.PartyID
	stateManager       storage.LocalStateManager
	commStopChan       chan struct{}
	p2pComm            *p2p.Communication
}

func NewMoneroKeyGen(localP2PID string,
	conf common.TssConfig,
	localNodePubKey string,
	broadcastChan chan *messages.BroadcastMsgChan,
	stopChan chan struct{},
	msgID string,
	stateManager storage.LocalStateManager,
	privateKey tcrypto.PrivKey,
	p2pComm *p2p.Communication) *MoneroKeyGen {
	return &MoneroKeyGen{
		logger: log.With().
			Str("module", "keygen").
			Str("msgID", msgID).Logger(),
		localNodePubKey:    localNodePubKey,
		moneroCommonStruct: common.NewTssCommon(localP2PID, broadcastChan, conf, msgID, privateKey),
		stopChan:           stopChan,
		localParty:         nil,
		stateManager:       stateManager,
		commStopChan:       make(chan struct{}),
		p2pComm:            p2pComm,
	}
}

func (tKeyGen *MoneroKeyGen) GetTssKeyGenChannels() chan *p2p.Message {
	return tKeyGen.moneroCommonStruct.TssMsg
}

func (tKeyGen *MoneroKeyGen) GetTssCommonStruct() *common.TssCommon {
	return tKeyGen.moneroCommonStruct
}

func (tKeyGen *MoneroKeyGen) packAndSend(info string, exchangeRound int, localPartyID *btss.PartyID, msgType string) error {
	sendShare := common.MoneroShare{
		MultisigInfo:  info,
		MsgType:       msgType,
		ExchangeRound: exchangeRound,
	}
	msg, err := json.Marshal(sendShare)
	if err != nil {
		tKeyGen.logger.Error().Err(err).Msg("fail to encode the wallet share")
		return err
	}

	r := btss.MessageRouting{
		From:        localPartyID,
		IsBroadcast: true,
	}
	return tKeyGen.moneroCommonStruct.ProcessOutCh(msg, &r, "moneroMsg", messages.TSSKeyGenMsg)
}

func (tKeyGen *MoneroKeyGen) GenerateNewKey(keygenReq Request) (string, error) {
	partiesID, localPartyID, err := conversion.GetParties(keygenReq.Keys, tKeyGen.localNodePubKey)
	if err != nil {
		return "", fmt.Errorf("fail to get keygen parties: %w", err)
	}

	threshold, err := conversion.GetThreshold(len(partiesID))
	if err != nil {
		return "", err
	}

	// since the defination of threshold of monero is different from the original tss, we need to adjust it 1 more node
	threshold += 1

	// now we try to connect to the monero wallet rpc client
	client := moneroWallet.New(moneroWallet.Config{
		Address: keygenReq.rpcAddress,
	})

	walletName := tKeyGen.localNodePubKey + ".mo"
	passcode := tKeyGen.GetTssCommonStruct().GetNodePrivKey()
	walletDat := moneroWallet.RequestCreateWallet{
		Filename: walletName,
		Password: passcode,
		Language: "English",
	}
	err = client.CreateWallet(&walletDat)
	if err != nil {
		return "", err
	}

	defer func() {
		err := client.CloseWallet()
		if err != nil {
			tKeyGen.logger.Error().Err(err).Msg("fail to close the created wallet")
		}
	}()

	blameMgr := tKeyGen.moneroCommonStruct.GetBlameMgr()

	partyIDMap := conversion.SetupPartyIDMap(partiesID)
	err1 := conversion.SetupIDMaps(partyIDMap, tKeyGen.moneroCommonStruct.PartyIDtoP2PID)
	err2 := conversion.SetupIDMaps(partyIDMap, blameMgr.PartyIDtoP2PID)
	if err1 != nil || err2 != nil {
		tKeyGen.logger.Error().Msgf("error in creating mapping between partyID and P2P ID")
		return "", err
	}

	partyInfo := &common.PartyInfo{
		Party:      nil,
		PartyIDMap: partyIDMap,
	}

	tKeyGen.moneroCommonStruct.SetPartyInfo(partyInfo)
	blameMgr.SetPartyInfo(nil, partyIDMap)
	tKeyGen.moneroCommonStruct.P2PPeers = conversion.GetPeersID(tKeyGen.moneroCommonStruct.PartyIDtoP2PID, tKeyGen.moneroCommonStruct.GetLocalPeerID())
	// start keygen
	defer tKeyGen.logger.Debug().Msg("generate monero share")

	moneroShareChan := make(chan *common.MoneroShare, len(partiesID))

	var address string

	var keyGenWg sync.WaitGroup
	keyGenWg.Add(1)
	go func() {
		tKeyGen.moneroCommonStruct.ProcessInboundMessages(tKeyGen.commStopChan, &keyGenWg, moneroShareChan)
	}()

	share, err := client.PrepareMultisig()
	if err != nil {
		return "", err
	}

	var exchangeRound int32
	exchangeRound = 0
	err = tKeyGen.packAndSend(share.MultisigInfo, int(exchangeRound), localPartyID, common.MoneroSharepre)
	if err != nil {
		return "", err
	}
	exchangeRound += 1

	var globalErr error
	peerNum := len(partiesID) - 1
	shareStore := monero_multi_sig.GenMoneroShareStore()
	keyGenWg.Add(1)
	go func() {
		defer keyGenWg.Done()
		for {
			select {
			case <-time.After(time.Minute * 10):
				close(tKeyGen.commStopChan)

			case share := <-moneroShareChan:
				switch share.MsgType {
				case common.MoneroSharepre:
					currentRound := atomic.LoadInt32(&exchangeRound)
					shares, ready := shareStore.StoreAndCheck(int(currentRound)-1, share, peerNum)
					if !ready {
						continue
					}
					dat := make([]string, len(shares))
					for i, el := range shares {
						dat[i] = el.MultisigInfo
					}
					request := moneroWallet.RequestMakeMultisig{
						MultisigInfo: dat,
						Threshold:    uint64(threshold),
						Password:     passcode,
					}
					resp, err := client.MakeMultisig(&request)
					if err != nil {
						globalErr = err
						return
					}

					err = tKeyGen.packAndSend(resp.MultisigInfo, int(currentRound), localPartyID, common.MoneroKeyGenShareExchange)
					if err != nil {
						globalErr = err
						return
					}
					atomic.AddInt32(&exchangeRound, 1)

				case common.MoneroKeyGenShareExchange:
					currentRound := atomic.LoadInt32(&exchangeRound)
					shares, ready := shareStore.StoreAndCheck(int(currentRound)-1, share, peerNum)
					if !ready {
						continue
					}
					dat := make([]string, len(shares))
					for i, el := range shares {
						dat[i] = el.MultisigInfo
					}

					finRequest := moneroWallet.RequestExchangeMultisigKeys{
						MultisigInfo: dat,
						Password:     passcode,
					}
					resp, err := client.ExchangeMultiSigKeys(&finRequest)
					if err != nil {
						globalErr = err
						return
					}
					// this indicate the wallet address is generated
					if len(resp.Address) != 0 {
						address = resp.Address
						err = tKeyGen.moneroCommonStruct.NotifyTaskDone()
						if err != nil {
							tKeyGen.logger.Error().Err(err).Msg("fail to broadcast the keysign done")
						}
						close(tKeyGen.commStopChan)
						return
					}

					err = tKeyGen.packAndSend(resp.MultisigInfo, int(currentRound), localPartyID, common.MoneroKeyGenShareExchange)
					if err != nil {
						globalErr = err
						return
					}
					atomic.AddInt32(&exchangeRound, 1)
				}
			case <-tKeyGen.moneroCommonStruct.GetTaskDone():
				close(tKeyGen.commStopChan)
			}
		}
	}()

	keyGenWg.Wait()
	if globalErr != nil {
		tKeyGen.logger.Error().Err(err).Msg("fail to create the monero multisig wallet")
	}
	tKeyGen.logger.Info().Msgf("wallet address is  %v\n", address)
	return address, err
}
