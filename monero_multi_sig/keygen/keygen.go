package keygen

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	bcrypto "github.com/binance-chain/tss-lib/crypto"
	bkg "github.com/binance-chain/tss-lib/ecdsa/keygen"
	btss "github.com/binance-chain/tss-lib/tss"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	tcrypto "github.com/tendermint/tendermint/crypto"

	moneroWallet "github.com/monero-ecosystem/go-monero-rpc-client/wallet"

	"gitlab.com/thorchain/tss/go-tss/common"
	"gitlab.com/thorchain/tss/go-tss/conversion"
	"gitlab.com/thorchain/tss/go-tss/messages"
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
	preParam *bkg.LocalPreParams,
	msgID string,
	stateManager storage.LocalStateManager,
	privateKey tcrypto.PrivKey,
	p2pComm *p2p.Communication) *MoneroKeyGen {
	return &MoneroKeyGen{
		logger: log.With().
			Str("module", "keygen").
			Str("msgID", msgID).Logger(),
		localNodePubKey:    localNodePubKey,
		preParams:          preParam,
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

func (tKeyGen *MoneroKeyGen) GetMoneroCommonStruct() *common.TssCommon {
	return tKeyGen.moneroCommonStruct
}

func (tKeyGen *MoneroKeyGen) packAndSend(info string, localPartyID *btss.PartyID, msgType string) error {
	sendShare := common.MoneroShare{
		MultisigInfo: info,
		MsgType:      msgType,
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

func (tKeyGen *MoneroKeyGen) GenerateNewKey(keygenReq Request) (*bcrypto.ECPoint, error) {
	partiesID, localPartyID, err := conversion.GetParties(keygenReq.Keys, tKeyGen.localNodePubKey)
	if err != nil {
		return nil, fmt.Errorf("fail to get keygen parties: %w", err)
	}

	threshold, err := conversion.GetThreshold(len(partiesID))
	if err != nil {
		return nil, err
	}

	// now we try to connect to the monero wallet rpc client

	client := moneroWallet.New(moneroWallet.Config{
		Address: keygenReq.rpcAddress,
	})

	walletName := tKeyGen.localNodePubKey + ".mo"
	passcode := tKeyGen.GetMoneroCommonStruct().GetNodePrivKey()
	walletDat := moneroWallet.RequestCreateWallet{
		Filename: walletName,
		Password: passcode,
		Language: "English",
	}
	err = client.CreateWallet(&walletDat)
	if err != nil {
		return nil, err
	}

	var keyGenWg sync.WaitGroup

	//ctx := btss.NewPeerContext(partiesID)
	//params := btss.NewParameters(ctx, localPartyID, len(partiesID), threshold)
	//if tKeyGen.preParams == nil {
	//	tKeyGen.logger.Error().Err(err).Msg("error, empty pre-parameters")
	//	return nil, errors.New("error, empty pre-parameters")
	//}

	blameMgr := tKeyGen.moneroCommonStruct.GetBlameMgr()

	outCh := make(chan btss.Message, len(partiesID))
	endCh := make(chan bkg.LocalPartySaveData, len(partiesID))

	ctx := btss.NewPeerContext(partiesID)
	params := btss.NewParameters(ctx, localPartyID, len(partiesID), threshold)
	keyGenParty := bkg.NewLocalParty(params, outCh, endCh, *tKeyGen.preParams)
	partyIDMap := conversion.SetupPartyIDMap(partiesID)
	err1 := conversion.SetupIDMaps(partyIDMap, tKeyGen.moneroCommonStruct.PartyIDtoP2PID)
	err2 := conversion.SetupIDMaps(partyIDMap, blameMgr.PartyIDtoP2PID)
	if err1 != nil || err2 != nil {
		tKeyGen.logger.Error().Msgf("error in creating mapping between partyID and P2P ID")
		return nil, err
	}

	partyInfo := &common.PartyInfo{
		Party:      keyGenParty,
		PartyIDMap: partyIDMap,
	}

	tKeyGen.moneroCommonStruct.SetPartyInfo(partyInfo)
	blameMgr.SetPartyInfo(keyGenParty, partyIDMap)
	tKeyGen.moneroCommonStruct.P2PPeers = conversion.GetPeersID(tKeyGen.moneroCommonStruct.PartyIDtoP2PID, tKeyGen.moneroCommonStruct.GetLocalPeerID())
	keyGenWg.Add(1)
	// start keygen
	defer tKeyGen.logger.Debug().Msg("generate monero share")

	moneroShareChan := make(chan *common.MoneroShare, len(partiesID))
	var sharespre, sharespre2, sharesfin []string
	var address string
	go func() {
		defer keyGenWg.Done()
		tKeyGen.moneroCommonStruct.ProcessInboundMessages(tKeyGen.commStopChan, &keyGenWg, moneroShareChan)
	}()

	share, err := client.PrepareMultisig()
	if err != nil {
		return nil, err
	}
	err = tKeyGen.packAndSend(share.MultisigInfo, localPartyID, common.MoneroSharepre)
	if err != nil {
		return nil, err
	}
	var globalErr error
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
					sharespre = append(sharespre, share.MultisigInfo)
					if len(sharespre) < len(partiesID)-1 {
						continue
					}
					request := moneroWallet.RequestMakeMultisig{
						MultisigInfo: sharespre,
						Threshold:    uint64(threshold),
						Password:     passcode,
					}
					resp, err := client.MakeMultisig(&request)
					if err != nil {
						globalErr = err
						return
					}

					err = tKeyGen.packAndSend(resp.MultisigInfo, localPartyID, common.MoneroSharepre2)
					if err != nil {
						globalErr = err
						return
					}

				case common.MoneroSharepre2:
					sharespre2 = append(sharespre2, share.MultisigInfo)
					if len(sharespre2) < len(partiesID)-1 {
						continue
					}
					fmt.Printf("we do exchange222222222>>>>>>>\n")
					finRequest := moneroWallet.RequestExchangeMultisigKeys{
						MultisigInfo: sharespre2,
						Password:     passcode,
					}
					resp, err := client.ExchangeMultiSigKeys(&finRequest)
					if err != nil {
						globalErr = err
						return
					}
					fmt.Printf("-2222#########-->%v@@@@@@@@@@@%v\n", resp.MultisigInfo, resp.Address)
					address = resp.Address
					err = tKeyGen.packAndSend(resp.MultisigInfo, localPartyID, common.MoneroSharepre3)
					if err != nil {
						globalErr = err
						return
					}

				case common.MoneroSharepre3:
					sharesfin = append(sharesfin, share.MultisigInfo)
					if len(sharesfin) < len(partiesID)-1 {
						continue
					}
					fmt.Printf("we do exchange333333>>>>>>>\n")
					finRequest := moneroWallet.RequestExchangeMultisigKeys{
						MultisigInfo: sharesfin,
						Password:     passcode,
					}
					resp, err := client.ExchangeMultiSigKeys(&finRequest)
					if err != nil {
						globalErr = err
						return
					}
					fmt.Printf("-33333#########-->%v@@@@@@@@@@@%v\n", resp.MultisigInfo, resp.Address)
					address = resp.Address
					err = tKeyGen.moneroCommonStruct.NotifyTaskDone()
					if err != nil {
						tKeyGen.logger.Error().Err(err).Msg("fail to broadcast the keysign done")
					}
					return
				}
			case <-tKeyGen.moneroCommonStruct.GetTaskDone():
				close(tKeyGen.commStopChan)
			}
		}
	}()
	if globalErr != nil {
		tKeyGen.logger.Error().Err(err).Msg("fail to create the monero multisig wallet")
	}

	keyGenWg.Wait()
	tKeyGen.logger.Info().Msgf("wallet address is  %v\n", address)
	return nil, err
}
