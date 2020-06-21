package conversion

import (
	"crypto/aes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/tendermint/tendermint/crypto"
	. "gopkg.in/check.v1"
)

type TssHelperTest struct {
	testPrivKey crypto.PrivKey
}

var _ = Suite(&TssHelperTest{})

func (p *TssHelperTest) SetUpTest(c *C) {
	encodedPrivkey := "ZThiMDAxOTk2MDc4ODk3YWE0YThlMjdkMWY0NjA1MTAwZDgyNDkyYzdhNmMwZWQ3MDBhMWIyMjNmNGMzYjVhYg=="
	priKey, err := GetPriKey(encodedPrivkey)
	c.Assert(err, IsNil)
	p.testPrivKey = priKey
}
func TestTssHelper(t *testing.T) { TestingT(t) }

func (p *TssHelperTest) TestAesEncryptionAndDecryption(c *C) {
	aesKey, err := GetAesKey(p.testPrivKey)
	c.Assert(err, IsNil)

	c.Assert(aesKey, HasLen, 32)
	testData := []byte("hello world")
	cipherText, err := AesEncryption(aesKey, testData)
	c.Assert(err, IsNil)
	plainText, err := AesDecryption(aesKey, cipherText)
	c.Assert(err, IsNil)
	c.Assert(plainText, DeepEquals, testData)

	wrongKey := "MzI5Zjc5YzI1MjAzMzIwNjAyOWI2OTI4ZWMwMmNmNzZlYmFkNTM3OWVmODlhYTVhMGY2ZTRiYjU2MGE3ZDgzZA=="
	wrongPriKey, err := GetPriKey(wrongKey)
	c.Assert(err, IsNil)
	wrongAesKey, err := GetAesKey(wrongPriKey)
	c.Assert(err, IsNil)
	_, err = AesDecryption(wrongAesKey, cipherText)
	c.Assert(err, ErrorMatches, "invalid message for unpadding")
}

func (p *TssHelperTest) TestAesEncryptionAndDecryption2(c *C) {
	aesKey, err := GetAesKey(p.testPrivKey)
	c.Assert(err, IsNil)
	testData := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, testData); err != nil {
		panic(err)
	}
	cipherText, err := AesEncryption(aesKey, testData)
	c.Assert(err, IsNil)
	plainText, err := AesDecryption(aesKey, cipherText)
	c.Assert(err, IsNil)
	c.Assert(plainText, DeepEquals, testData)
}
