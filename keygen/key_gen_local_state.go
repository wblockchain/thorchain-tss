package keygen

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"path"
	"path/filepath"

	"github.com/binance-chain/tss-lib/ecdsa/keygen"

	"gitlab.com/thorchain/tss/go-tss/common"
)

// KeyGenReq request to do keygen
type KeyGenReq struct {
	Keys []string `json:"keys"`
}

// KeyGenResp keygen response
type KeyGenResp struct {
	PubKey      string        `json:"pub_key"`
	PoolAddress string        `json:"pool_address"`
	Status      common.Status `json:"status"`
	Blame       common.Blame  `json:"blame"`
}

func NewKeyGenReq(keys []string) KeyGenReq {
	return KeyGenReq{
		Keys: keys,
	}
}

func NewKeyGenResp(pk, addr string, status common.Status, blame common.Blame) KeyGenResp {
	return KeyGenResp{
		PubKey:      pk,
		PoolAddress: addr,
		Status:      status,
		Blame:       blame,
	}
}

func SaveLocalStateToFile(filePathName string, state common.KeygenLocalStateItem) error {
	buf, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("fail to marshal KeygenLocalState to json: %w", err)
	}
	return ioutil.WriteFile(filePathName, buf, 0655)
}

func (tKeyGen *TssKeyGen) AddLocalPartySaveData(homeBase string, data keygen.LocalPartySaveData, keyGenLocalStateItem common.KeygenLocalStateItem) error {
	pubKey, addr, err := common.GetTssPubKey(data.ECDSAPub)
	if err != nil {
		return fmt.Errorf("fail to get thorchain pubkey: %w", err)
	}
	tKeyGen.logger.Debug().Msgf("pubkey: %s, bnb address: %s", pubKey, addr)
	keyGenLocalStateItem.PubKey = pubKey
	keyGenLocalStateItem.LocalData = data
	localFileName := fmt.Sprintf("localstate-%s.json", pubKey)
	if len(homeBase) > 0 {
		localFileName = filepath.Join(homeBase, localFileName)
	}
	if path.Dir(homeBase) == "." {
		tKeyGen.logger.Error().Msgf("file path does not exist")
		return errors.New("error path not exist")
	}
	return SaveLocalStateToFile(localFileName, keyGenLocalStateItem)
}