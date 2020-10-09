package conversion

import (
	"bytes"
	"errors"
	"math/rand"
	"sort"
	"strconv"

	"github.com/blang/semver"
	sdk "github.com/cosmos/cosmos-sdk/types"
	atypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	p2pcrypto "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/tendermint/tendermint/crypto"
	"github.com/tendermint/tendermint/crypto/secp256k1"

	tcrypto "github.com/tendermint/tendermint/crypto"
)

// GetRandomPubKey for test
func GetRandomPubKey() string {
	_, pubKey, _ := atypes.KeyTestPubAddr()
	bech32PubKey, _ := sdk.Bech32ifyPubKey(sdk.Bech32PubKeyTypeAccPub, pubKey)
	return bech32PubKey
}

// GetRandomPeerID for test
func GetRandomPeerID() peer.ID {
	_, pubKey, _ := atypes.KeyTestPubAddr()
	peerID, _ := GetPeerIDFromSecp256PubKey(pubKey.(secp256k1.PubKeySecp256k1))
	return peerID
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const (
	letterIdxBits = 6                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
)

func RandStringBytesMask(n int) string {
	b := make([]byte, n)
	for i := 0; i < n; {
		if idx := int(rand.Int63() & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i++
		}
	}
	return string(b)
}

func VersionLTCheck(currentVer, expectedVer string) (bool, error) {
	c, err := semver.Make(expectedVer)
	if err != nil {
		return false, errors.New("fail to parse the expected version")
	}
	v, err := semver.Make(currentVer)
	if err != nil {
		return false, errors.New("fail to parse the current version")
	}
	return v.LT(c), nil
}

func VersionGECheck(currentVer, expectedVer string) (bool, error) {
	c, err := semver.Make(expectedVer)
	if err != nil {
		return false, errors.New("fail to parse the expected version")
	}
	v, err := semver.Make(currentVer)
	if err != nil {
		return false, errors.New("fail to parse the current version")
	}
	return v.GE(c), nil
}

// as we want to make the p2p signature verification independent from the tss, so we generate the signature
// that suitable for the public key verification derived from the peer ID.
func GenerateP2PSignature(privKey tcrypto.PrivKey, msg []byte) ([]byte, error) {
	privKeyRaw, err := GetPriKeyRawBytes(privKey)
	if err != nil {
		return nil, err
	}
	p2pPriKey, err := p2pcrypto.UnmarshalSecp256k1PrivateKey(privKeyRaw)
	if err != nil {
		return nil, err
	}
	sig, err := p2pPriKey.Sign(msg)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func GenerateSignature(msg []byte, msgID string, privKey crypto.PrivKey) ([]byte, error) {
	var dataForSigning bytes.Buffer
	dataForSigning.Write(msg)
	dataForSigning.WriteString(msgID)
	return privKey.Sign(dataForSigning.Bytes())
}

func VerifySignature(pubKey crypto.PubKey, message, sig []byte, msgID string) bool {
	var dataForSign bytes.Buffer
	dataForSign.Write(message)
	dataForSign.WriteString(msgID)
	return pubKey.VerifyBytes(dataForSign.Bytes(), sig)
}

func GetHighestFreq(in map[string]string) (string, int, error) {
	if len(in) == 0 {
		return "", 0, errors.New("empty input")
	}
	freq := make(map[string]int, len(in))
	hashPeerMap := make(map[string]string, len(in))
	for peerID, n := range in {
		freq[n]++
		hashPeerMap[n] = peerID
	}

	sFreq := make([][2]string, 0, len(freq))
	for n, f := range freq {
		sFreq = append(sFreq, [2]string{n, strconv.FormatInt(int64(f), 10)})
	}
	sort.Slice(sFreq, func(i, j int) bool {
		if sFreq[i][1] > sFreq[j][1] {
			return true
		} else {
			return false
		}
	},
	)
	freqInt, err := strconv.Atoi(sFreq[0][1])
	if err != nil {
		return "", 0, err
	}
	return sFreq[0][0], freqInt, nil
}
