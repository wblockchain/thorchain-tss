package monero_multi_sig

import (
	"encoding/base64"
	"encoding/json"
	"sync"

	"gitlab.com/thorchain/tss/go-tss/common"
)

// since monero wallet is slow in synchronization, we need to have the retry
const MoneroWalletRetry = 20

type MoneroSharesStore struct {
	shares map[int][]*common.MoneroShare
	locker sync.Mutex
}

type MoneroPrepareMsg struct {
	ExchangeInfo string   `json:"exchange_info"`
	Pubkeys      []string `json:"pubkeys_info"`
}

func GenMoneroShareStore() *MoneroSharesStore {
	shares := make(map[int][]*common.MoneroShare)
	return &MoneroSharesStore{
		shares,
		sync.Mutex{},
	}
}

func (ms *MoneroSharesStore) StoreAndCheck(round int, share *common.MoneroShare, checkLength int) ([]*common.MoneroShare, bool) {
	ms.locker.Lock()
	defer ms.locker.Unlock()
	shares, ok := ms.shares[round]
	if ok {
		for _, el := range shares {
			if el.Equal(share) {
				panic("should not store the same share again")
			}
		}

		shares = append(shares, share)
		ms.shares[round] = shares
		if len(shares) == checkLength {
			return shares, true
		}
		return shares, false
	}
	ms.shares[round] = []*common.MoneroShare{share}
	return ms.shares[round], false
}

func EncodePrePareInfo(exportedMultiSigInfo string, exportedPubKeys []string) (string, error) {
	prepareMsg := MoneroPrepareMsg{
		ExchangeInfo: exportedMultiSigInfo,
		Pubkeys:      exportedPubKeys,
	}
	out, err := json.Marshal(prepareMsg)
	return base64.StdEncoding.EncodeToString(out), err
}

func DecodePrePareInfo(in string) (MoneroPrepareMsg, error) {
	out, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return MoneroPrepareMsg{}, err
	}
	var dat MoneroPrepareMsg
	err = json.Unmarshal(out, &dat)
	return dat, err
}
