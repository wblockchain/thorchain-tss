package conversion

import (
	"testing"

	p2pcrypto "github.com/libp2p/go-libp2p-core/crypto"

	"github.com/stretchr/testify/assert"
	"github.com/tendermint/tendermint/crypto/secp256k1"
)

func TestVersionCheck(t *testing.T) {
	expectedVer := "1.4.0"
	currentVer := "1.3.0"
	ret, err := VersionLTCheck(currentVer, expectedVer)
	assert.Equal(t, err, nil)
	assert.Equal(t, ret, true)

	expectedVerErr := "none"
	_, err = VersionLTCheck(currentVer, expectedVerErr)
	assert.Equal(t, err.Error(), "fail to parse the expected version")
	currentVer = "abc"
	_, err = VersionLTCheck(currentVer, expectedVer)
	assert.Equal(t, err.Error(), "fail to parse the current version")

	expectedVer = "1.2.0"
	currentVer = "1.3.0"
	ret, err = VersionLTCheck(currentVer, expectedVer)
	assert.Equal(t, err, nil)
	assert.Equal(t, ret, false)

	currentVer = "1.2.2"
	expectedVer = "1.2.0"
	ret, err = VersionLTCheck(currentVer, expectedVer)
	assert.Equal(t, err, nil)
	assert.Equal(t, ret, false)

	expectedVer = "0.14.0"
	currentVer = "0.13.9"
	ret, err = VersionLTCheck(currentVer, expectedVer)
	assert.Equal(t, err, nil)
	assert.Equal(t, ret, true)

	expectedVer = "0.14.0"
	currentVer = "0.14.0"
	ret, err = VersionLTCheck(currentVer, expectedVer)
	assert.Equal(t, err, nil)
	assert.Equal(t, ret, false)
}

func TestMsgSignAndVerification(t *testing.T) {
	msg := []byte("hello")
	msgID := "123"
	sk := secp256k1.GenPrivKey()
	sig, err := GenerateSignature(msg, msgID, sk)
	assert.Equal(t, err, nil)
	assert.Equal(t, err, nil)
	ret := VerifySignature(sk.PubKey(), msg, sig, msgID)
	assert.Equal(t, ret, true)
}

func TestGenerateP2PSignature(t *testing.T) {
	sk, err := GetPriKey("YmNiMzA2ODU1NWNjMzk3NDE1OWMwMTM3MDU0NTNjN2YwMzYzZmVhZDE5NmU3NzRhOTMwOWIxN2QyZTQ0MzdkNg==")
	assert.Equal(t, err, nil)
	privKeyRaw, err := GetPriKeyRawBytes(sk)
	assert.Equal(t, err, nil)
	p2pPriKey, err := p2pcrypto.UnmarshalSecp256k1PrivateKey(privKeyRaw)
	assert.Equal(t, err, nil)
	sig, err := GenerateP2PSignature(sk, []byte("hello"))
	assert.Equal(t, err, nil)
	ret, err := p2pPriKey.GetPublic().Verify([]byte("hello"), sig)
	assert.Equal(t, err, nil)
	assert.Equal(t, ret, true)
}

func TestGetHashToBroadcast(t *testing.T) {
	testMap := make(map[string]string)
	_, _, err := GetHighestFreq(testMap)
	assert.NotNil(t, err)
	_, _, err = GetHighestFreq(nil)
	assert.NotNil(t, err)
	testMap["1"] = "aa"
	testMap["2"] = "aa"
	testMap["3"] = "aa"
	testMap["4"] = "ab"
	testMap["5"] = "bb"
	testMap["6"] = "bb"
	testMap["7"] = "bc"
	testMap["8"] = "cd"
	val, freq, err := GetHighestFreq(testMap)
	assert.Equal(t, err, nil)
	assert.Equal(t, val, "aa")
	assert.Equal(t, freq, 3)
}
