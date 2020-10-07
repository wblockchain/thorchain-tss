package conversion

import (
	"testing"

	"github.com/magiconair/properties/assert"
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
