package monero_multi_sig

import "sync"

type MoneroSharesStore struct {
	shares map[int][]string
	locker sync.Mutex
}

func GenMoneroShareStore() *MoneroSharesStore {
	shares := make(map[int][]string)
	return &MoneroSharesStore{
		shares,
		sync.Mutex{},
	}
}

func (ms *MoneroSharesStore) StoreAndCheck(round int, share string, checkLength int) ([]string, bool) {
	ms.locker.Lock()
	defer ms.locker.Unlock()
	shares, ok := ms.shares[round]
	if ok {

		for _, el := range shares {
			if el == share {
				panic("should not equal")
			}
		}

		shares = append(shares, share)
		ms.shares[round] = shares
		if len(shares) == checkLength {
			return shares, true
		}
		return shares, false
	}
	ms.shares[round] = []string{share}
	return ms.shares[round], false
}
