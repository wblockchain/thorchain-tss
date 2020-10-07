package conversion

import (
	"bytes"
	"errors"
	"math/rand"

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
