package tss

import (
	"time"

	btsskeygen "github.com/binance-chain/tss-lib/ecdsa/keygen"

	"gitlab.com/thorchain/tss/go-tss/blame"
	"gitlab.com/thorchain/tss/go-tss/common"
	"gitlab.com/thorchain/tss/go-tss/conversion"
	"gitlab.com/thorchain/tss/go-tss/messages"
	"gitlab.com/thorchain/tss/go-tss/regroup"
)

func (t *TssServer) KeyRegroup(req keyRegroup.Request) (keyRegroup.Response, error) {
	t.tssKeyGenLocker.Lock()
	defer t.tssKeyGenLocker.Unlock()
	status := common.Success
	msgID, err := t.requestToMsgId(req)
	if err != nil {
		return keyRegroup.Response{}, err
	}

	var localPartyData btsskeygen.LocalPartySaveData
	if req.PoolPubKey != "" {
		localSaveData, err := t.stateManager.GetLocalState(req.PoolPubKey)
		if err != nil {
			t.logger.Error().Err(err).Msgf("fail to get the local State data")
			return keyRegroup.NewResponse("", "", common.Fail, blame.Blame{}), err
		}
		localPartyData = localSaveData.LocalData
	} else {
		localPartyData.LocalPreParams = *t.preParams
	}

	keyRegroupInstance := keyRegroup.NewTssKeyReGroup(
		t.p2pCommunication.GetLocalPeerID(),
		t.conf,
		t.localNodePubKey,
		t.p2pCommunication.BroadcastMsgChan,
		t.stopChan,
		t.preParams,
		msgID,
		t.stateManager, t.privateKey, t.p2pCommunication)

	keygenMsgChannel := keyRegroupInstance.GetTssKeyGenChannels()

	t.p2pCommunication.SetSubscribe(messages.TSSPartyReGroup, msgID, keygenMsgChannel)
	t.p2pCommunication.SetSubscribe(messages.TSSPartReGroupVerMSg, msgID, keygenMsgChannel)
	t.p2pCommunication.SetSubscribe(messages.TSSControlMsg, msgID, keygenMsgChannel)
	t.p2pCommunication.SetSubscribe(messages.TSSTaskDone, msgID, keygenMsgChannel)
	defer func() {
		t.p2pCommunication.CancelSubscribe(messages.TSSPartyReGroup, msgID)
		t.p2pCommunication.CancelSubscribe(messages.TSSPartReGroupVerMSg, msgID)
		t.p2pCommunication.CancelSubscribe(messages.TSSControlMsg, msgID)
		t.p2pCommunication.CancelSubscribe(messages.TSSTaskDone, msgID)
	}()

	sigChan := make(chan string)
	blameMgr := keyRegroupInstance.GetTssCommonStruct().GetBlameMgr()
	joinPartyStartTime := time.Now()
	// TODO current, we ask all the old committee members to be involved in regroup to delete their shares
	// TODO otherwise, the node need to delete the key share themselves.
	var allKeys []string
	allKeysContainer := make(map[string]bool)
	for _, el := range append(req.OldPartyKeys, req.NewPartyKeys...) {
		allKeysContainer[el] = true
	}
	for key, _ := range allKeysContainer {
		allKeys = append(allKeys, key)
	}
	onlinePeers, leader, errJoinParty := t.joinParty(msgID, req.Version, req.BlockHeight, allKeys, len(allKeys)-1, sigChan)
	joinPartyTime := time.Since(joinPartyStartTime)
	if errJoinParty != nil {
		t.tssMetrics.KeygenJoinParty(joinPartyTime, false)
		t.tssMetrics.UpdateKeyGen(0, false)
		// this indicate we are processing the leaderless join party
		if leader == "NONE" {
			if onlinePeers == nil {
				t.logger.Error().Err(err).Msg("error before we start join party")
				return keyRegroup.Response{
					Status: common.Fail,
					Blame:  blame.NewBlame(blame.InternalError, []blame.Node{}),
				}, nil
			}
			blameNodes, err := blameMgr.NodeSyncBlame(allKeys, onlinePeers)
			if err != nil {
				t.logger.Err(errJoinParty).Msg("fail to get peers to blame")
			}
			// make sure we blame the leader as well
			t.logger.Error().Err(errJoinParty).Msgf("fail to form keygen party with online:%v", onlinePeers)
			return keyRegroup.Response{
				Status: common.Fail,
				Blame:  blameNodes,
			}, nil

		}

		var blameLeader blame.Blame
		var blameNodes blame.Blame
		blameNodes, err = blameMgr.NodeSyncBlame(allKeys, onlinePeers)
		if err != nil {
			t.logger.Err(errJoinParty).Msg("fail to get peers to blame")
		}
		leaderPubKey, err := conversion.GetPubKeyFromPeerID(leader)
		if err != nil {
			t.logger.Error().Err(errJoinParty).Msgf("fail to convert the peerID to public key with leader %s", leader)
			blameLeader = blame.NewBlame(blame.TssSyncFail, []blame.Node{})
		} else {
			blameLeader = blame.NewBlame(blame.TssSyncFail, []blame.Node{{leaderPubKey, nil, nil}})
		}
		if len(onlinePeers) != 0 {
			blameNodes.AddBlameNodes(blameLeader.BlameNodes...)
		} else {
			blameNodes = blameLeader
		}
		t.logger.Error().Err(errJoinParty).Msgf("fail to form keygen party with online:%v", onlinePeers)

		return keyRegroup.Response{
			Status: common.Fail,
			Blame:  blameNodes,
		}, nil

	}

	t.tssMetrics.KeygenJoinParty(joinPartyTime, true)
	t.logger.Debug().Msg("keygen party formed")

	// the statistic of keygen only care about Tss it self, even if the
	// following http response aborts, it still counted as a successful keygen
	// as the Tss model runs successfully.
	beforeKeygen := time.Now()
	k, err := keyRegroupInstance.GenerateNewKey(req, localPartyData)
	keygenTime := time.Since(beforeKeygen)
	if err != nil {
		t.tssMetrics.UpdateKeyGen(keygenTime, false)
		t.logger.Error().Err(err).Msg("err in keygen")
		blameNodes := *blameMgr.GetBlame()
		return keyRegroup.NewResponse("", "", common.Fail, blameNodes), err
	} else {
		t.tssMetrics.UpdateKeyGen(keygenTime, true)
	}

	amNewMember := false
	for _, el := range req.NewPartyKeys {
		if t.localNodePubKey == el {
			amNewMember = true
			break
		}
	}

	blameNodes := *blameMgr.GetBlame()
	if !amNewMember {
		return keyRegroup.NewResponse(
			"",
			"",
			common.Success,
			blameNodes,
		), nil
	}

	newPubKey, addr, err := conversion.GetTssPubKey(k)
	if err != nil {
		t.logger.Error().Err(err).Msg("fail to generate the new Tss key")
		status = common.Fail
	}

	return keyRegroup.NewResponse(
		newPubKey,
		addr.String(),
		status,
		blameNodes,
	), nil
}
