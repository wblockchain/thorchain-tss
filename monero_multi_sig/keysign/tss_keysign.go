package keysign

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/binance-chain/tss-lib/ecdsa/keygen"
	"github.com/binance-chain/tss-lib/ecdsa/signing"
	btss "github.com/binance-chain/tss-lib/tss"
	moneroWallet "github.com/monero-ecosystem/go-monero-rpc-client/wallet"
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

type MoneroKeySign struct {
	logger             zerolog.Logger
	moneroCommonStruct *common.TssCommon
	localNodePubKey    string
	stopChan           chan struct{} // channel to indicate whether we should stop
	localParty         *btss.PartyID
	commStopChan       chan struct{}
	p2pComm            *p2p.Communication
	stateManager       storage.LocalStateManager
}

func NewMoneroKeySign(localP2PID string,
	conf common.TssConfig,
	broadcastChan chan *messages.BroadcastMsgChan,
	stopChan chan struct{}, localNodePubKey, msgID string, privKey tcrypto.PrivKey, p2pComm *p2p.Communication, stateManager storage.LocalStateManager) *MoneroKeySign {
	logItems := []string{"keySign", msgID}
	return &MoneroKeySign{
		logger:             log.With().Strs("module", logItems).Logger(),
		localNodePubKey:    localNodePubKey,
		moneroCommonStruct: common.NewTssCommon(localP2PID, broadcastChan, conf, msgID, privKey),
		stopChan:           stopChan,
		localParty:         nil,
		commStopChan:       make(chan struct{}),
		p2pComm:            p2pComm,
		stateManager:       stateManager,
	}
}

func (tKeySign *MoneroKeySign) GetTssKeySignChannels() chan *p2p.Message {
	return tKeySign.moneroCommonStruct.TssMsg
}

func (tKeySign *MoneroKeySign) GetTssCommonStruct() *common.TssCommon {
	return tKeySign.moneroCommonStruct
}

func (tKeySign *MoneroKeySign) amIFirstNode(msgID, localPubKey string, parties []string) (string, bool) {
	keyStore := make(map[string]string)
	hashes := make([]string, len(parties))
	for i, el := range parties {
		sum := sha256.Sum256([]byte(msgID + el))
		encodedSum := hex.EncodeToString(sum[:])
		keyStore[encodedSum] = el
		hashes[i] = encodedSum
	}
	sort.Strings(hashes)
	leader := keyStore[hashes[0]]
	return leader, leader == localPubKey
}

func (tKeySign *MoneroKeySign) packAndSend(info string, exchangeRound int, localPartyID *btss.PartyID, msgType string) error {
	sendShare := common.MoneroShare{
		MultisigInfo:  info,
		MsgType:       msgType,
		ExchangeRound: exchangeRound,
	}
	msg, err := json.Marshal(sendShare)
	if err != nil {
		tKeySign.logger.Error().Err(err).Msg("fail to encode the wallet share")
		return err
	}

	r := btss.MessageRouting{
		From:        localPartyID,
		IsBroadcast: true,
	}
	return tKeySign.moneroCommonStruct.ProcessOutCh(msg, &r, "moneroMsg", messages.TSSKeyGenMsg)
}

// signMessage
func (tKeySign *MoneroKeySign) SignMessage(rpcAddress, encodedTx string, parties []string) (*signing.SignatureData, error) {
	partiesID, localPartyID, err := conversion.GetParties(parties, tKeySign.localNodePubKey)
	tKeySign.localParty = localPartyID
	if err != nil {
		return nil, fmt.Errorf("fail to form key sign party: %w", err)
	}

	if !common.Contains(partiesID, localPartyID) {
		tKeySign.logger.Info().Msgf("we are not in this rounds key sign")
		return nil, nil
	}

	tKeySign.logger.Debug().Msgf("local party: %+v", localPartyID)

	ctx := btss.NewPeerContext(partiesID)
	params := btss.NewParameters(ctx, localPartyID, len(partiesID), 1)
	outCh := make(chan btss.Message, len(partiesID))
	endCh := make(chan *signing.SignatureData, len(partiesID))
	errCh := make(chan struct{})
	blameMgr := tKeySign.moneroCommonStruct.GetBlameMgr()

	dummy := keygen.LocalPartySaveData{}
	keySignParty := signing.NewLocalParty(big.NewInt(0), params, dummy, outCh, endCh)
	partyIDMap := conversion.SetupPartyIDMap(partiesID)
	err1 := conversion.SetupIDMaps(partyIDMap, tKeySign.moneroCommonStruct.PartyIDtoP2PID)
	err2 := conversion.SetupIDMaps(partyIDMap, blameMgr.PartyIDtoP2PID)
	if err1 != nil || err2 != nil {
		tKeySign.logger.Error().Err(err).Msgf("error in creating mapping between partyID and P2P ID")
		return nil, err
	}

	tKeySign.moneroCommonStruct.SetPartyInfo(&common.PartyInfo{
		Party:      keySignParty,
		PartyIDMap: partyIDMap,
	})

	blameMgr.SetPartyInfo(keySignParty, partyIDMap)
	tKeySign.moneroCommonStruct.P2PPeers = conversion.GetPeersID(tKeySign.tssCommonStruct.PartyIDtoP2PID, tKeySign.tssCommonStruct.GetLocalPeerID())
	var keySignWg sync.WaitGroup
	keySignWg.Add(2)

	// now we try to connect to the monero wallet rpc client
	client := moneroWallet.New(moneroWallet.Config{
		Address: rpcAddress,
	})

	walletName := tKeySign.localNodePubKey + tKeySign.GetTssCommonStruct().GetMsgID() + ".mo"
	passcode := tKeySign.GetTssCommonStruct().GetNodePrivKey()
	// now open the wallet
	req := moneroWallet.RequestOpenWallet{
		Filename: walletName,
		Password: passcode,
	}
	err = client.OpenWallet(&req)
	if err != nil {
		return nil, err
	}

	dat, err := base64.StdEncoding.DecodeString(encodedTx)
	if err != nil {
		tKeySign.logger.Error().Err(err).Msg("fail to decode the transaction")
		return nil, err
	}

	var tx moneroWallet.RequestTransfer
	err = json.Unmarshal(dat, &tx)
	if err != nil {
		tKeySign.logger.Error().Err(err).Msg("fail to unmarshal the transaction")
		return nil, err
	}

	leader, isLeader := tKeySign.amIFirstNode(encodedTx, tKeySign.localNodePubKey, parties)

	var responseTransfer *moneroWallet.ResponseTransfer
	if isLeader {
		responseTransfer, err = client.Transfer(&tx)
		if err != nil {
			tKeySign.logger.Error().Err(err).Msg("fail to create the transfer data")
			return nil, err
		}
	}
	var exchangeRound int32
	exchangeRound = 0
	err = tKeySign.packAndSend(responseTransfer.MultisigTxset, int(exchangeRound), localPartyID, common.MoneroSharepre)
	if err != nil {
		return nil, err
	}
	exchangeRound += 1

	// modify!!!!!!

	// start the key sign
	go func() {
		defer keySignWg.Done()
		if err := keySignParty.Start(); nil != err {
			tKeySign.logger.Error().Err(err).Msg("fail to start key sign party")
			close(errCh)
		}
		tKeySign.tssCommonStruct.SetPartyInfo(&common.PartyInfo{
			Party:      keySignParty,
			PartyIDMap: partyIDMap,
		})
		tKeySign.logger.Debug().Msg("local party is ready")
	}()
	go tKeySign.tssCommonStruct.ProcessInboundMessages(tKeySign.commStopChan, &keySignWg)
	result, err := tKeySign.processKeySign(errCh, outCh, endCh)
	if err != nil {
		close(tKeySign.commStopChan)
		return nil, fmt.Errorf("fail to process key sign: %w", err)
	}

	select {
	case <-time.After(time.Second * 5):
		close(tKeySign.commStopChan)
	case <-tKeySign.tssCommonStruct.GetTaskDone():
		close(tKeySign.commStopChan)
	}
	keySignWg.Wait()

	tKeySign.logger.Info().Msgf("%s successfully sign the message", tKeySign.p2pComm.GetHost().ID().String())
	return result, nil
}

func (tKeySign *MoneroKeySign) processKeySign(errChan chan struct{}, outCh <-chan btss.Message, endCh <-chan *signing.SignatureData) (*signing.SignatureData, error) {
	defer tKeySign.logger.Debug().Msg("key sign finished")
	tKeySign.logger.Debug().Msg("start to read messages from local party")
	tssConf := tKeySign.tssCommonStruct.GetConf()
	blameMgr := tKeySign.tssCommonStruct.GetBlameMgr()

	for {
		select {
		case <-errChan: // when key sign return
			tKeySign.logger.Error().Msg("key sign failed")
			return nil, errors.New("error channel closed fail to start local party")
		case <-tKeySign.stopChan: // when TSS processor receive signal to quit
			return nil, errors.New("received exit signal")
		case <-time.After(tssConf.KeySignTimeout):
			// we bail out after KeySignTimeoutSeconds
			tKeySign.logger.Error().Msgf("fail to sign message with %s", tssConf.KeySignTimeout.String())
			lastMsg := blameMgr.GetLastMsg()
			failReason := blameMgr.GetBlame().FailReason
			if failReason == "" {
				failReason = blame.TssTimeout
			}
			threshold, err := conversion.GetThreshold(len(tKeySign.tssCommonStruct.P2PPeers) + 1)
			if err != nil {
				tKeySign.logger.Error().Err(err).Msg("error in get the threshold for generate blame")
			}
			if !lastMsg.IsBroadcast() {
				blameNodesUnicast, err := blameMgr.GetUnicastBlame(lastMsg.Type())
				if err != nil {
					tKeySign.logger.Error().Err(err).Msg("error in get unicast blame")
				}
				if len(blameNodesUnicast) > 0 && len(blameNodesUnicast) <= threshold {
					blameMgr.GetBlame().SetBlame(failReason, blameNodesUnicast, true)
				}
			} else {
				blameNodesUnicast, err := blameMgr.GetUnicastBlame(conversion.GetPreviousKeySignUicast(lastMsg.Type()))
				if err != nil {
					tKeySign.logger.Error().Err(err).Msg("error in get unicast blame")
				}
				if len(blameNodesUnicast) > 0 && len(blameNodesUnicast) <= threshold {
					blameMgr.GetBlame().SetBlame(failReason, blameNodesUnicast, true)
				}
			}

			blameNodesBroadcast, err := blameMgr.GetBroadcastBlame(lastMsg.Type())
			if err != nil {
				tKeySign.logger.Error().Err(err).Msg("error in get broadcast blame")
			}
			blameMgr.GetBlame().AddBlameNodes(blameNodesBroadcast...)

			// if we cannot find the blame node, we check whether everyone send me the share
			if len(blameMgr.GetBlame().BlameNodes) == 0 {
				blameNodesMisingShare, isUnicast, err := blameMgr.TssMissingShareBlame(messages.TSSKEYSIGNROUNDS)
				if err != nil {
					tKeySign.logger.Error().Err(err).Msg("fail to get the node of missing share ")
				}

				if len(blameNodesMisingShare) > 0 && len(blameNodesMisingShare) <= threshold {
					blameMgr.GetBlame().AddBlameNodes(blameNodesMisingShare...)
					blameMgr.GetBlame().IsUnicast = isUnicast
				}
			}

			return nil, blame.ErrTssTimeOut
		case msg := <-outCh:
			tKeySign.logger.Debug().Msgf(">>>>>>>>>>key sign msg: %s", msg.String())
			tKeySign.tssCommonStruct.GetBlameMgr().SetLastMsg(msg)
			buf, r, err := msg.WireBytes()
			// if we cannot get the wire share, the tss keygen will fail, we just quit.
			if err != nil {
				return nil, errors.New("invalid tss message")
			}
			err = tKeySign.tssCommonStruct.ProcessOutCh(buf, r, msg.Type(), messages.TSSKeySignMsg)
			if err != nil {
				return nil, err
			}

		case msg := <-endCh:
			tKeySign.logger.Debug().Msg("we have done the key sign")
			err := tKeySign.tssCommonStruct.NotifyTaskDone()
			if err != nil {
				tKeySign.logger.Error().Err(err).Msg("fail to broadcast the keysign done")
			}
			address := tKeySign.p2pComm.ExportPeerAddress()
			if err := tKeySign.stateManager.SaveAddressBook(address); err != nil {
				tKeySign.logger.Error().Err(err).Msg("fail to save the peer addresses")
			}
			return msg, nil
		}
	}
}

func (tKeySign *MoneroKeySign) WriteKeySignResult(w http.ResponseWriter, R, S, recovertID string, status common.Status) {
	signResp := Response{
		R:          R,
		S:          S,
		RecoveryID: recovertID,
		Status:     status,
		Blame:      *tKeySign.tssCommonStruct.GetBlameMgr().GetBlame(),
	}
	jsonResult, err := json.MarshalIndent(signResp, "", "	")
	if err != nil {
		tKeySign.logger.Error().Err(err).Msg("fail to marshal response to json message")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, err = w.Write(jsonResult)
	if err != nil {
		tKeySign.logger.Error().Err(err).Msg("fail to write response")
	}
}
