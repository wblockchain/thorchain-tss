package tss

import (
	"errors"
	"gitlab.com/thorchain/tss/go-tss/keygen/ecdsa"
	"gitlab.com/thorchain/tss/go-tss/keygen/eddsa"
	"time"

	"gitlab.com/thorchain/binance-sdk/common/types"
	"gitlab.com/thorchain/tss/go-tss/blame"
	"gitlab.com/thorchain/tss/go-tss/common"
	"gitlab.com/thorchain/tss/go-tss/conversion"
	"gitlab.com/thorchain/tss/go-tss/keygen"
	"gitlab.com/thorchain/tss/go-tss/messages"
)

func (t *TssServer) Keygen(req keygen.Request) (keygen.Response, error) {
	t.tssKeyGenLocker.Lock()
	defer t.tssKeyGenLocker.Unlock()
	status := common.Success
	msgID, err := t.requestToMsgId(req)
	if err != nil {
		return keygen.Response{}, err
	}

	var keygenInstance keygen.TssKeyGen
	switch req.Algo {
	case "ecdsa":
		keygenInstance = ecdsa.NewTssKeyGen(
			t.p2pCommunication.GetLocalPeerID(),
			t.conf,
			t.localNodePubKey,
			t.p2pCommunication.BroadcastMsgChan,
			t.stopChan,
			t.preParams,
			msgID,
			t.stateManager,
			t.privateKey,
			t.p2pCommunication)
	case "eddsa":
		keygenInstance = eddsa.NewTssKeyGen(
			t.p2pCommunication.GetLocalPeerID(),
			t.conf,
			t.localNodePubKey,
			t.p2pCommunication.BroadcastMsgChan,
			t.stopChan,
			msgID,
			t.stateManager,
			t.privateKey,
			t.p2pCommunication)
	default:
		return keygen.Response{}, errors.New("invalid keygen algo")
	}

	keygenMsgChannel := keygenInstance.GetTssKeyGenChannels()
	t.p2pCommunication.SetSubscribe(messages.TSSKeyGenMsg, msgID, keygenMsgChannel)
	t.p2pCommunication.SetSubscribe(messages.TSSKeyGenVerMsg, msgID, keygenMsgChannel)
	t.p2pCommunication.SetSubscribe(messages.TSSControlMsg, msgID, keygenMsgChannel)
	t.p2pCommunication.SetSubscribe(messages.TSSTaskDone, msgID, keygenMsgChannel)

	defer func() {
		t.p2pCommunication.CancelSubscribe(messages.TSSKeyGenMsg, msgID)
		t.p2pCommunication.CancelSubscribe(messages.TSSKeyGenVerMsg, msgID)
		t.p2pCommunication.CancelSubscribe(messages.TSSControlMsg, msgID)
		t.p2pCommunication.CancelSubscribe(messages.TSSTaskDone, msgID)

		t.p2pCommunication.ReleaseStream(msgID)
		t.partyCoordinator.ReleaseStream(msgID)
	}()
	sigChan := make(chan string)
	blameMgr := keygenInstance.GetTssCommonStruct().GetBlameMgr()
	joinPartyStartTime := time.Now()
	onlinePeers, leader, errJoinParty := t.joinParty(msgID, req.Version, req.BlockHeight, req.Keys, len(req.Keys)-1, sigChan)
	joinPartyTime := time.Since(joinPartyStartTime)
	if errJoinParty != nil {
		t.tssMetrics.KeygenJoinParty(joinPartyTime, false)
		t.tssMetrics.UpdateKeyGen(0, false)
		// this indicate we are processing the leaderless join party
		if leader == "NONE" {
			if onlinePeers == nil {
				t.logger.Error().Err(err).Msg("error before we start join party")
				return keygen.Response{
					Status: common.Fail,
					Blame:  blame.NewBlame(blame.InternalError, []blame.Node{}),
				}, nil
			}
			blameNodes, err := blameMgr.NodeSyncBlame(req.Keys, onlinePeers)
			if err != nil {
				t.logger.Err(errJoinParty).Msg("fail to get peers to blame")
			}
			// make sure we blame the leader as well
			t.logger.Error().Err(errJoinParty).Msgf("fail to form keygen party with online:%v", onlinePeers)
			return keygen.Response{
				Status: common.Fail,
				Blame:  blameNodes,
			}, nil

		}

		var blameLeader blame.Blame
		var blameNodes blame.Blame
		blameNodes, err = blameMgr.NodeSyncBlame(req.Keys, onlinePeers)
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

		return keygen.Response{
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
	k, err := keygenInstance.GenerateNewKey(req)
	keygenTime := time.Since(beforeKeygen)
	if err != nil {
		t.tssMetrics.UpdateKeyGen(keygenTime, false)
		t.logger.Error().Err(err).Msg("err in keygen")
		blameNodes := *blameMgr.GetBlame()
		return keygen.NewResponse("", "", common.Fail, blameNodes), err
	} else {
		t.tssMetrics.UpdateKeyGen(keygenTime, true)
	}

	blameNodes := *blameMgr.GetBlame()
	var newPubKey string
	var addr types.AccAddress
	switch req.Algo {
	case "ecdsa":
		newPubKey, addr, err = conversion.GetTssPubKeyECDSA(k)
	case "eddsa":
		newPubKey, addr, err = conversion.GetTssPubKeyEDDSA(k)
	default:
		newPubKey, addr, err = conversion.GetTssPubKeyECDSA(k)
	}
	if err != nil {
		t.logger.Error().Err(err).Msg("fail to generate the new Tss key")
		status = common.Fail
	}
	return keygen.NewResponse(
		newPubKey,
		addr.String(),
		status,
		blameNodes,
	), nil
}

func (t *TssServer) KeygenAllAlgo(req keygen.Request) ([]keygen.Response, error) {
	// this is the algo we currently support
	algos := []string{"ecdsa", "eddsa"}
	if req.Algo != "" {
		t.logger.Error().Msgf("algo should be empty when invoking keygenallAlgo")
		return nil, errors.New("algo should be empty")
	}
	t.tssKeyGenLocker.Lock()
	defer t.tssKeyGenLocker.Unlock()
	status := common.Success
	msgID, err := t.requestToMsgId(req)
	if err != nil {
		return nil, err
	}

	ecdsaKeygenInstance := ecdsa.NewTssKeyGen(
		t.p2pCommunication.GetLocalPeerID(),
		t.conf,
		t.localNodePubKey,
		t.p2pCommunication.BroadcastMsgChan,
		t.stopChan,
		t.preParams,
		msgID+"ecdsa",
		t.stateManager,
		t.privateKey,
		t.p2pCommunication)

	eddsaKeygenInstance := eddsa.NewTssKeyGen(
		t.p2pCommunication.GetLocalPeerID(),
		t.conf,
		t.localNodePubKey,
		t.p2pCommunication.BroadcastMsgChan,
		t.stopChan,
		msgID+"eddsa",
		t.stateManager,
		t.privateKey,
		t.p2pCommunication)
	_ = eddsaKeygenInstance
	_ = ecdsaKeygenInstance
	keygenInstances := make(map[string]keygen.TssKeyGen)
	keygenInstances["ecdsa"] = ecdsaKeygenInstance
	keygenInstances["eddsa"] = eddsaKeygenInstance

	for algo, instance := range keygenInstances {
		msgID := msgID + algo
		keygenMsgChannel := instance.GetTssKeyGenChannels()
		t.p2pCommunication.SetSubscribe(messages.TSSKeyGenMsg, msgID, keygenMsgChannel)
		t.p2pCommunication.SetSubscribe(messages.TSSKeyGenVerMsg, msgID, keygenMsgChannel)
		t.p2pCommunication.SetSubscribe(messages.TSSControlMsg, msgID, keygenMsgChannel)
		t.p2pCommunication.SetSubscribe(messages.TSSTaskDone, msgID, keygenMsgChannel)

		defer func() {
			t.p2pCommunication.CancelSubscribe(messages.TSSKeyGenMsg, msgID)
			t.p2pCommunication.CancelSubscribe(messages.TSSKeyGenVerMsg, msgID)
			t.p2pCommunication.CancelSubscribe(messages.TSSControlMsg, msgID)
			t.p2pCommunication.CancelSubscribe(messages.TSSTaskDone, msgID)

			t.p2pCommunication.ReleaseStream(msgID)
			t.partyCoordinator.ReleaseStream(msgID)
		}()
	}
	sigChan := make(chan string)
	// since all the keygen algorithms share the join party, so we need to use the ecdsa algo's blame manager
	blameMgr := keygenInstances["ecdsa"].GetTssCommonStruct().GetBlameMgr()
	joinPartyStartTime := time.Now()
	onlinePeers, leader, errJoinParty := t.joinParty(msgID, req.Version, req.BlockHeight, req.Keys, len(req.Keys)-1, sigChan)
	joinPartyTime := time.Since(joinPartyStartTime)
	if errJoinParty != nil {
		t.tssMetrics.KeygenJoinParty(joinPartyTime, false)
		t.tssMetrics.UpdateKeyGen(0, false)
		// this indicate we are processing the leaderless join party
		if leader == "NONE" {
			if onlinePeers == nil {
				t.logger.Error().Err(err).Msg("error before we start join party")
				return []keygen.Response{{
					Status: common.Fail,
					Blame:  blame.NewBlame(blame.InternalError, []blame.Node{}),
				}}, nil
			}
			blameNodes, err := blameMgr.NodeSyncBlame(req.Keys, onlinePeers)
			if err != nil {
				t.logger.Err(errJoinParty).Msg("fail to get peers to blame")
			}
			// make sure we blame the leader as well
			t.logger.Error().Err(errJoinParty).Msgf("fail to form keygen party with online:%v", onlinePeers)
			return []keygen.Response{{
				Status: common.Fail,
				Blame:  blameNodes,
			}}, nil

		}

		var blameLeader blame.Blame
		var blameNodes blame.Blame
		blameNodes, err = blameMgr.NodeSyncBlame(req.Keys, onlinePeers)
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

		return []keygen.Response{{
			Status: common.Fail,
			Blame:  blameNodes,
		}}, nil

	}

	t.tssMetrics.KeygenJoinParty(joinPartyTime, true)
	t.logger.Debug().Msg("keygen party formed")
	// the statistic of keygen only care about Tss it self, even if the
	// following http response aborts, it still counted as a successful keygen
	// as the Tss model runs successfully.
	beforeKeygen := time.Now()

	var responseKeys []keygen.Response
	var blameNode blame.Blame
	var keygenErr error
	for _, algo := range algos {
		instance := keygenInstances[algo]
		k, keygenErr := instance.GenerateNewKey(req)
		keygenTime := time.Since(beforeKeygen)
		if keygenErr != nil {
			t.tssMetrics.UpdateKeyGen(keygenTime, false)
			t.logger.Error().Err(keygenErr).Msg("err in keygen")
			blameMgr := instance.GetTssCommonStruct().GetBlameMgr()
			blameNode = *blameMgr.GetBlame()
			break
		} else {
			t.tssMetrics.UpdateKeyGen(keygenTime, true)
		}

		blameNodes := *blameMgr.GetBlame()
		var newPubKey string
		var addr types.AccAddress
		switch algo {
		case "ecdsa":
			newPubKey, addr, keygenErr = conversion.GetTssPubKeyECDSA(k)
		case "eddsa":
			newPubKey, addr, keygenErr = conversion.GetTssPubKeyEDDSA(k)
		default:
			newPubKey, addr, keygenErr = conversion.GetTssPubKeyECDSA(k)
		}
		if keygenErr != nil {
			t.logger.Error().Err(keygenErr).Msg("fail to generate the new Tss key")
			status = common.Fail
			break
		}
		resp := keygen.NewResponse(
			newPubKey,
			addr.String(),
			status,
			blameNodes,
		)
		responseKeys = append(responseKeys, resp)
	}

	if keygenErr != nil || status != common.Success {
		return []keygen.Response{{
			Status: common.Fail,
			Blame:  blameNode,
		}}, nil
	}

	return responseKeys, nil
}
