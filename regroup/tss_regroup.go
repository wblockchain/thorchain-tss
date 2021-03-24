package keygen

import (
	"errors"
	"fmt"
	"sync"
	"time"

	bcrypto "github.com/binance-chain/tss-lib/crypto"
	bkg "github.com/binance-chain/tss-lib/ecdsa/keygen"
	btss "github.com/binance-chain/tss-lib/tss"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	tcrypto "github.com/tendermint/tendermint/crypto"

	"gitlab.com/thorchain/tss/go-tss/blame"
	"gitlab.com/thorchain/tss/go-tss/common"
	"gitlab.com/thorchain/tss/go-tss/conversion"
	"gitlab.com/thorchain/tss/go-tss/messages"
	"gitlab.com/thorchain/tss/go-tss/p2p"
	"gitlab.com/thorchain/tss/go-tss/storage"
)

type TssKeyReGroup struct {
	logger          zerolog.Logger
	localNodePubKey string
	preParams       *bkg.LocalPreParams
	tssCommonStruct *common.TssCommon
	stopChan        chan struct{} // channel to indicate whether we should stop
	localParty      *btss.PartyID
	stateManager    storage.LocalStateManager
	commStopChan    chan struct{}
	p2pComm         *p2p.Communication
}

func NewTssKeyReGroup(localP2PID string,
	conf common.TssConfig,
	localNodePubKey string,
	broadcastChan chan *messages.BroadcastMsgChan,
	stopChan chan struct{},
	preParam *bkg.LocalPreParams,
	msgID string,
	stateManager storage.LocalStateManager,
	privateKey tcrypto.PrivKey,
	p2pComm *p2p.Communication) *TssKeyReGroup {
	return &TssKeyReGroup{
		logger: log.With().
			Str("module", "keygen").
			Str("msgID", msgID).Logger(),
		localNodePubKey: localNodePubKey,
		preParams:       preParam,
		tssCommonStruct: common.NewTssCommon(localP2PID, broadcastChan, conf, msgID, privateKey, 1),
		stopChan:        stopChan,
		localParty:      nil,
		stateManager:    stateManager,
		commStopChan:    make(chan struct{}),
		p2pComm:         p2pComm,
	}
}

func (tKeyReGroup *TssKeyReGroup) GetTssKeyGenChannels() chan *p2p.Message {
	return tKeyReGroup.tssCommonStruct.TssMsg
}

func (tKeyReGroup *TssKeyReGroup) GetTssCommonStruct() *common.TssCommon {
	return tKeyReGroup.tssCommonStruct
}

func (tKeyReGroup *TssKeyReGroup) GenerateNewKey(keygenReq Request, localStateItem storage.KeygenLocalState, parties []string) (*bcrypto.ECPoint, error) {
	var params *btss.ReSharingParameters
	threshold, err := conversion.GetThreshold(len(keygenReq.NewPartyKeys))
	if err != nil {
		return nil, errors.New("fail to get threshold")
	}
	if localStateItem.PubKey == "" {
		// we are the new party
		newPartiesID, localPartyID, err := conversion.GetParties(keygenReq.NewPartyKeys, tKeyReGroup.localNodePubKey, true)
		if err != nil {
			return nil, fmt.Errorf("fail to get keygen parties: %w", err)
		}
		oldPartiesID, _, err := conversion.GetParties(keygenReq.OldPartyKeys, tKeyReGroup.localNodePubKey, true)
		if err != nil {
			return nil, fmt.Errorf("fail to get keygen parties: %w", err)
		}

		ctxNew := btss.NewPeerContext(newPartiesID)
		ctxOld := btss.NewPeerContext(oldPartiesID)

		params = btss.NewReSharingParameters(ctxOld, ctxNew, localPartyID, len(keygenReq.NewPartyKeys), threshold, len(keygenReq.NewPartyKeys), threshold)
	}

	partiesID, localPartyID, err := conversion.GetParties(parties, localStateItem.LocalPartyKey)
	if err != nil {
		return nil, fmt.Errorf("fail to form key sign party: %w", err)
	}
	if !common.Contains(partiesID, localPartyID) {
		tKeyReGroup.logger.Info().Msgf("we are not in this rounds key sign")
		return nil, nil
	}
	threshold, err := conversion.GetThreshold(len(localStateItem.ParticipantKeys))
	if err != nil {
		return nil, errors.New("fail to get threshold")
	}

	partiesID, localPartyID, err := conversion.GetParties(keygenReq.Keys, tKeyReGroup.localNodePubKey)
	if err != nil {
		return nil, fmt.Errorf("fail to get keygen parties: %w", err)
	}

	keyGenLocalStateItem := storage.KeygenLocalState{
		ParticipantKeys: keygenReq.Keys,
		LocalPartyKey:   tKeyReGroup.localNodePubKey,
	}

	threshold, err := conversion.GetThreshold(len(partiesID))
	if err != nil {
		return nil, err
	}
	keyGenPartyMap := new(sync.Map)
	ctx := btss.NewPeerContext(partiesID)
	params := btss.NewParameters(ctx, localPartyID, len(partiesID), threshold)
	outCh := make(chan btss.Message, len(partiesID))
	endCh := make(chan bkg.LocalPartySaveData, len(partiesID))
	errChan := make(chan struct{})
	if tKeyReGroup.preParams == nil {
		tKeyReGroup.logger.Error().Err(err).Msg("error, empty pre-parameters")
		return nil, errors.New("error, empty pre-parameters")
	}
	blameMgr := tKeyReGroup.tssCommonStruct.GetBlameMgr()
	keyGenParty := bkg.NewLocalParty(params, outCh, endCh, *tKeyReGroup.preParams)
	partyIDMap := conversion.SetupPartyIDMap(partiesID)
	err1 := conversion.SetupIDMaps(partyIDMap, tKeyReGroup.tssCommonStruct.PartyIDtoP2PID)
	err2 := conversion.SetupIDMaps(partyIDMap, blameMgr.PartyIDtoP2PID)
	if err1 != nil || err2 != nil {
		tKeyReGroup.logger.Error().Msgf("error in creating mapping between partyID and P2P ID")
		return nil, err
	}
	// we never run multi keygen, so the moniker is set to default empty value
	keyGenPartyMap.Store("", keyGenParty)
	partyInfo := &common.PartyInfo{
		PartyMap:   keyGenPartyMap,
		PartyIDMap: partyIDMap,
	}

	tKeyReGroup.tssCommonStruct.SetPartyInfo(partyInfo)
	blameMgr.SetPartyInfo(keyGenPartyMap, partyIDMap)
	tKeyReGroup.tssCommonStruct.P2PPeersLock.Lock()
	tKeyReGroup.tssCommonStruct.P2PPeers = conversion.GetPeersID(tKeyReGroup.tssCommonStruct.PartyIDtoP2PID, tKeyReGroup.tssCommonStruct.GetLocalPeerID())
	tKeyReGroup.tssCommonStruct.P2PPeersLock.Unlock()
	var keyGenWg sync.WaitGroup
	keyGenWg.Add(2)
	// start keygen
	go func() {
		defer keyGenWg.Done()
		defer tKeyReGroup.logger.Debug().Msg(">>>>>>>>>>>>>.keyGenParty started")
		if err := keyGenParty.Start(); nil != err {
			tKeyReGroup.logger.Error().Err(err).Msg("fail to start keygen party")
			close(errChan)
		}
	}()
	go tKeyReGroup.tssCommonStruct.ProcessInboundMessages(tKeyReGroup.commStopChan, &keyGenWg)

	r, err := tKeyReGroup.processKeyGen(errChan, outCh, endCh, keyGenLocalStateItem)
	if err != nil {
		close(tKeyReGroup.commStopChan)
		return nil, fmt.Errorf("fail to process key sign: %w", err)
	}
	select {
	case <-time.After(time.Second * 5):
		close(tKeyReGroup.commStopChan)

	case <-tKeyReGroup.tssCommonStruct.GetTaskDone():
		close(tKeyReGroup.commStopChan)
	}

	keyGenWg.Wait()
	return r, err
}

func (tKeyReGroup *TssKeyReGroup) processKeyGen(errChan chan struct{},
	outCh <-chan btss.Message,
	endCh <-chan bkg.LocalPartySaveData,
	keyGenLocalStateItem storage.KeygenLocalState) (*bcrypto.ECPoint, error) {
	defer tKeyReGroup.logger.Debug().Msg("finished keygen process")
	tKeyReGroup.logger.Debug().Msg("start to read messages from local party")
	tssConf := tKeyReGroup.tssCommonStruct.GetConf()
	blameMgr := tKeyReGroup.tssCommonStruct.GetBlameMgr()
	for {
		select {
		case <-errChan: // when keyGenParty return
			tKeyReGroup.logger.Error().Msg("key gen failed")
			return nil, errors.New("error channel closed fail to start local party")

		case <-tKeyReGroup.stopChan: // when TSS processor receive signal to quit
			return nil, errors.New("received exit signal")

		case <-time.After(tssConf.KeyGenTimeout):
			// we bail out after KeyGenTimeoutSeconds
			tKeyReGroup.logger.Error().Msgf("fail to generate message with %s", tssConf.KeyGenTimeout.String())
			lastMsg := blameMgr.GetLastMsg()
			failReason := blameMgr.GetBlame().FailReason
			if failReason == "" {
				failReason = blame.TssTimeout
			}
			if lastMsg == nil {
				tKeyReGroup.logger.Error().Msg("fail to start the keygen, the last produced message of this node is none")
				return nil, errors.New("timeout before shared message is generated")
			}
			blameNodesUnicast, err := blameMgr.GetUnicastBlame(messages.KEYGEN2aUnicast)
			if err != nil {
				tKeyReGroup.logger.Error().Err(err).Msg("error in get unicast blame")
			}
			tKeyReGroup.tssCommonStruct.P2PPeersLock.RLock()
			threshold, err := conversion.GetThreshold(len(tKeyReGroup.tssCommonStruct.P2PPeers) + 1)
			tKeyReGroup.tssCommonStruct.P2PPeersLock.RUnlock()
			if err != nil {
				tKeyReGroup.logger.Error().Err(err).Msg("error in get the threshold to generate blame")
			}

			if len(blameNodesUnicast) > 0 && len(blameNodesUnicast) <= threshold {
				blameMgr.GetBlame().SetBlame(failReason, blameNodesUnicast, true)
			}
			blameNodesBroadcast, err := blameMgr.GetBroadcastBlame(lastMsg.Type())
			if err != nil {
				tKeyReGroup.logger.Error().Err(err).Msg("error in get broadcast blame")
			}
			blameMgr.GetBlame().AddBlameNodes(blameNodesBroadcast...)

			// if we cannot find the blame node, we check whether everyone send me the share
			if len(blameMgr.GetBlame().BlameNodes) == 0 {
				blameNodesMisingShare, isUnicast, err := blameMgr.TssMissingShareBlame(messages.TSSKEYGENROUNDS)
				if err != nil {
					tKeyReGroup.logger.Error().Err(err).Msg("fail to get the node of missing share ")
				}
				if len(blameNodesMisingShare) > 0 && len(blameNodesMisingShare) <= threshold {
					blameMgr.GetBlame().AddBlameNodes(blameNodesMisingShare...)
					blameMgr.GetBlame().IsUnicast = isUnicast
				}
			}
			return nil, blame.ErrTssTimeOut

		case msg := <-outCh:
			tKeyReGroup.logger.Debug().Msgf(">>>>>>>>>>msg: %s", msg.String())
			blameMgr.SetLastMsg(msg)
			err := tKeyReGroup.tssCommonStruct.ProcessOutCh(msg, messages.TSSKeyGenMsg)
			if err != nil {
				tKeyReGroup.logger.Error().Err(err).Msg("fail to process the message")
				return nil, err
			}

		case msg := <-endCh:
			tKeyReGroup.logger.Debug().Msgf("keygen finished successfully: %s", msg.ECDSAPub.Y().String())
			err := tKeyReGroup.tssCommonStruct.NotifyTaskDone()
			if err != nil {
				tKeyReGroup.logger.Error().Err(err).Msg("fail to broadcast the keysign done")
			}
			pubKey, _, err := conversion.GetTssPubKey(msg.ECDSAPub)
			if err != nil {
				return nil, fmt.Errorf("fail to get thorchain pubkey: %w", err)
			}
			keyGenLocalStateItem.LocalData = msg
			keyGenLocalStateItem.PubKey = pubKey
			if err := tKeyReGroup.stateManager.SaveLocalState(keyGenLocalStateItem); err != nil {
				return nil, fmt.Errorf("fail to save keygen result to storage: %w", err)
			}
			address := tKeyReGroup.p2pComm.ExportPeerAddress()
			if err := tKeyReGroup.stateManager.SaveAddressBook(address); err != nil {
				tKeyReGroup.logger.Error().Err(err).Msg("fail to save the peer addresses")
			}
			return msg.ECDSAPub, nil
		}
	}
}
