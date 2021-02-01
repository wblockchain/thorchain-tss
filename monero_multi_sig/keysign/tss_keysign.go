package keysign

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/binance-chain/tss-lib/ecdsa/signing"
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

type MoneroKeySign struct {
	logger             zerolog.Logger
	moneroCommonStruct *common.TssCommon
	localNodePubKey    string
	stopChan           chan struct{} // channel to indicate whether we should stop
	localParty         *btss.PartyID
	commStopChan       chan struct{}
	p2pComm            *p2p.Communication
	stateManager       storage.LocalStateManager
	walletClient       moneroWallet.Client
}

func NewMoneroKeySign(localP2PID string,
	conf common.TssConfig,
	broadcastChan chan *messages.BroadcastMsgChan,
	stopChan chan struct{}, localNodePubKey, msgID string, privKey tcrypto.PrivKey, p2pComm *p2p.Communication) *MoneroKeySign {
	logItems := []string{"keySign", msgID}
	return &MoneroKeySign{
		logger:             log.With().Strs("module", logItems).Logger(),
		localNodePubKey:    localNodePubKey,
		moneroCommonStruct: common.NewTssCommon(localP2PID, broadcastChan, conf, msgID, privKey),
		stopChan:           stopChan,
		localParty:         nil,
		commStopChan:       make(chan struct{}),
		p2pComm:            p2pComm,
	}
}

func (tKeySign *MoneroKeySign) GetTssKeySignChannels() chan *p2p.Message {
	return tKeySign.moneroCommonStruct.TssMsg
}

func (tKeySign *MoneroKeySign) GetTssCommonStruct() *common.TssCommon {
	return tKeySign.moneroCommonStruct
}

func (tKeySign *MoneroKeySign) amIFirstNode(msgID string, parties []string) ([]string, int) {
	keyStore := make(map[string]string)
	hashes := make([]string, len(parties))
	for i, el := range parties {
		sum := sha256.Sum256([]byte(msgID + el))
		encodedSum := hex.EncodeToString(sum[:])
		keyStore[encodedSum] = el
		hashes[i] = encodedSum
	}
	sort.Strings(hashes)

	var sortedOrder []string
	myIndex := 0
	myIndexFound := false
	for i := 0; i < len(keyStore); i++ {
		if tKeySign.localNodePubKey == keyStore[hashes[i]] {
			myIndexFound = true
		}
		sortedOrder = append(sortedOrder, keyStore[hashes[i]])
		if !myIndexFound {
			myIndex += 1
		}
	}
	return sortedOrder, myIndex
}

func (tKeySign *MoneroKeySign) packAndSend(info string, exchangeRound int, localPartyID, toParty *btss.PartyID, msgType string) error {
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

	if toParty == nil {
		r := btss.MessageRouting{
			From:        localPartyID,
			IsBroadcast: true,
		}
		return tKeySign.moneroCommonStruct.ProcessOutCh(msg, &r, "moneroMsg", messages.TSSKeySignMsg)
	}
	r := btss.MessageRouting{
		From:        localPartyID,
		To:          []*btss.PartyID{toParty},
		IsBroadcast: false,
	}
	return tKeySign.moneroCommonStruct.ProcessOutCh(msg, &r, "moneroMsg", messages.TSSKeySignMsg)
}

func (tKeySign *MoneroKeySign) submitSignature(signature string) ([]string, error) {
	client2Submit := moneroWallet.RequestSubmitMultisig{
		TxDataHex: signature,
	}
	signedTxHash, err := tKeySign.walletClient.SubmitMultisig(&client2Submit)
	return signedTxHash.TxHashList, err
}

func (tKeySign *MoneroKeySign) genOrderedParties(orderedNodes []string, parties map[string]*btss.PartyID) ([]*btss.PartyID, error) {
	var orderedParties []*btss.PartyID
	for _, target := range orderedNodes {
		for _, el := range parties {
			pubkey, err := conversion.PartyIDtoPubKey(el)
			if err != nil {
				return nil, err
			}
			if pubkey == target {
				orderedParties = append(orderedParties, el)
			}
		}
	}
	return orderedParties, nil
}

// signMessage
func (tKeySign *MoneroKeySign) SignMessage(rpcAddress, encodedTx string, parties []string) (*signing.SignatureData, error) {
	var globalErr error
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

	blameMgr := tKeySign.moneroCommonStruct.GetBlameMgr()

	partyIDMap := conversion.SetupPartyIDMap(partiesID)
	err1 := conversion.SetupIDMaps(partyIDMap, tKeySign.moneroCommonStruct.PartyIDtoP2PID)
	err2 := conversion.SetupIDMaps(partyIDMap, blameMgr.PartyIDtoP2PID)
	if err1 != nil || err2 != nil {
		tKeySign.logger.Error().Err(err).Msgf("error in creating mapping between partyID and P2P ID")
		return nil, err
	}

	tKeySign.moneroCommonStruct.SetPartyInfo(&common.PartyInfo{
		Party:      nil,
		PartyIDMap: partyIDMap,
	})

	blameMgr.SetPartyInfo(nil, partyIDMap)
	tKeySign.moneroCommonStruct.P2PPeers = conversion.GetPeersID(tKeySign.moneroCommonStruct.PartyIDtoP2PID, tKeySign.moneroCommonStruct.GetLocalPeerID())
	var keySignWg sync.WaitGroup

	// now we try to connect to the monero wallet rpc client
	tKeySign.walletClient = moneroWallet.New(moneroWallet.Config{
		Address: rpcAddress,
	})

	walletName := tKeySign.localNodePubKey + ".mo"
	// walletName := "1" + ".mo"
	passcode := tKeySign.GetTssCommonStruct().GetNodePrivKey()
	passcode = "123"
	// now open the wallet
	req := moneroWallet.RequestOpenWallet{
		Filename: walletName,
		Password: passcode,
	}

	err = tKeySign.walletClient.OpenWallet(&req)
	if err != nil {
		return nil, err
	}
	defer func() {
		err := tKeySign.walletClient.CloseWallet()
		if err != nil {
			tKeySign.logger.Error().Err(err).Msg("fail to close the wallet")
		}
	}()

	walletInfo, err := tKeySign.walletClient.IsMultisig()
	if err != nil {
		tKeySign.logger.Error().Err(err).Msg("fail to query the wallet info")
		return nil, err
	}
	if !walletInfo.Multisig || !walletInfo.Ready {
		tKeySign.logger.Error().Err(err).Msg("it is not a multisig wallet or wallet is not ready")
		return nil, errors.New("not a multisig wallet or wallet is not ready(keygen done correctly?)")
	}
	balanceReq := moneroWallet.RequestGetBalance{
		AccountIndex: 0,
	}
	counter := 0
	for ; counter < 10; counter++ {
		time.Sleep(time.Second * 1)
		balance, err := tKeySign.walletClient.GetBalance(&balanceReq)
		if err != nil {
		}
		if balance.UnlockedBalance > 1 {
			tKeySign.logger.Info().Msgf("unlock balance is %v\n", balance.UnlockedBalance)
			break
		}
	}
	if counter >= 10 {
		return nil, errors.New("not enough fund in wallet")
	}

	threshold := walletInfo.Threshold
	needToWait := threshold - 1 // we do not need to wait for ourselves

	tx, err := base64.StdEncoding.DecodeString(encodedTx)
	if err != nil {
		tKeySign.logger.Error().Err(err).Msg("fail to decode the transaction")
		return nil, err
	}

	var txSend moneroWallet.RequestTransfer
	err = json.Unmarshal(tx, &txSend)
	if err != nil {
		tKeySign.logger.Error().Err(err).Msg("fail to unmarshal the transaction")
		return nil, err
	}

	// inport message
	orderedNodes, myIndex := tKeySign.amIFirstNode(tKeySign.GetTssCommonStruct().GetMsgID(), parties)
	leader := orderedNodes[0]

	orderedParties, err := tKeySign.genOrderedParties(orderedNodes, partyIDMap)
	if err != nil {
		tKeySign.logger.Error().Err(err).Msg("fail to get the ordered parties")
		return nil, err
	}

	isLeader := leader == tKeySign.localNodePubKey
	var responseTransfer *moneroWallet.ResponseTransfer
	moneroShareChan := make(chan *common.MoneroShare, len(partiesID))

	keySignWg.Add(1)
	go func() {
		tKeySign.moneroCommonStruct.ProcessInboundMessages(tKeySign.commStopChan, &keySignWg, moneroShareChan)
	}()

	// we exchange the prepre info
	exportedMultisigInfo, err := tKeySign.walletClient.ExportMultisigInfo()
	if err != nil {
		return nil, err
	}
	err = tKeySign.packAndSend(exportedMultisigInfo.Info, 0, localPartyID, nil, common.MoneroExportedSignMsg)
	if err != nil {
		return nil, err
	}

	shareStore := monero_multi_sig.GenMoneroShareStore()
	var myShare string
	keySignWg.Add(1)
	go func() {
		defer func() {
			keySignWg.Done()
			close(tKeySign.commStopChan)
		}()
		for {
			select {
			case <-time.After(time.Minute * 10):
				close(tKeySign.commStopChan)

			case share := <-moneroShareChan:
				switch share.MsgType {
				case common.MoneroExportedSignMsg:
					shares, ready := shareStore.StoreAndCheck(0, share.MultisigInfo, int(needToWait))
					if !ready {
						continue
					}

					info := moneroWallet.RequestImportMultisigInfo{
						Info: shares,
					}
					_, err := tKeySign.walletClient.ImportMultisigInfo(&info)
					if err != nil {
						tKeySign.logger.Error().Err(err).Msg("fail to import the multisig info")
						globalErr = err
						return
					}

					// if we are the leader, we need to initialise the wallet.
					if isLeader {
						responseTransfer, err = tKeySign.walletClient.Transfer(&txSend)
						if err != nil {
							tKeySign.logger.Error().Err(err).Msg("fail to create the transfer data")
							// we will handle the error in the upper level
							return
						}

						err = tKeySign.packAndSend(responseTransfer.MultisigTxset, 1, localPartyID, orderedParties[myIndex+1], common.MoneroInitTransfer)
						if err != nil {
							// fixme notify the failure of keysign
							tKeySign.logger.Error().Err(err).Msg("fail to send the initialization transfer info")
							globalErr = err
							return
						}
						tKeySign.logger.Info().Msg("leader have done the signature preparation")
						return
					}
					// fixme what other nodes should do?
					tKeySign.logger.Info().Msgf("we(%s) have done the signature preparation", tKeySign.localNodePubKey)

				case common.MoneroInitTransfer, common.MoneroSignShares:
					if myIndex == 0 || (share.Sender == leader && myIndex != 1) || (share.Sender != orderedNodes[myIndex-1]) {
						continue
					}
					outData := moneroWallet.RequestSignMultisig{
						TxDataHex: share.MultisigInfo,
					}
					ret, err := tKeySign.walletClient.SignMultisig(&outData)
					if err != nil {
						globalErr = err
						tKeySign.logger.Error().Err(err).Msg("fail to sign the transaction")
						return
					}

					if myIndex == int(threshold-1) {
						//	globalErr = tKeySign.moneroCommonStruct.NotifyTaskDone()
						//	if globalErr != nil {
						//		tKeySign.logger.Error().Err(err).Msg("fail to broadcast the keysign done")
						//		return
						//	}
						//	return
						//}
						// we are the last node
						//resp, globalErr := tKeySign.submitSignature(ret.TxDataHex)
						//if globalErr != nil {
						//	tKeySign.logger.Error().Err(globalErr).Msg("fail to submit the signature")
						//}
						tKeySign.logger.Info().Msg("################we have signed the signature successfully")
						return
					}
					myShare = ret.TxDataHex
					err = tKeySign.packAndSend(myShare, 1, localPartyID, orderedParties[myIndex+1], common.MoneroSignShares)
					if err != nil {
						globalErr = err
						return
					}
					return
				}

			case <-tKeySign.moneroCommonStruct.GetTaskDone():
				fmt.Printf(">>>>>>>>>>>>>node %s quit", tKeySign.localNodePubKey)
				return

			}
		}
	}()

	keySignWg.Wait()
	if globalErr != nil {
		return nil, globalErr
	}

	tKeySign.logger.Debug().Msgf("%s successfully sign the message", tKeySign.p2pComm.GetHost().ID().String())
	return nil, nil
}
