package conversion

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/pbkdf2"

	tcrypto "github.com/tendermint/tendermint/crypto"

	"github.com/btcsuite/btcd/btcec"

	atypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/tendermint/tendermint/crypto/secp256k1"
)

// GetRandomPeerID for test
func GetRandomPeerID() peer.ID {
	_, pubKey, _ := atypes.KeyTestPubAddr()
	peerID, _ := GetPeerIDFromSecp256PubKey(pubKey.(secp256k1.PubKeySecp256k1))
	return peerID
}

func MsgToHashInt(msg []byte) (*big.Int, error) {
	return hashToInt(msg, btcec.S256()), nil
}

func MsgToHashString(msg []byte) (string, error) {
	if len(msg) == 0 {
		return "", errors.New("empty message")
	}
	h := sha256.New()
	_, err := h.Write(msg)
	if err != nil {
		return "", fmt.Errorf("fail to caculate sha256 hash: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashToInt(hash []byte, c elliptic.Curve) *big.Int {
	orderBits := c.Params().N.BitLen()
	orderBytes := (orderBits + 7) / 8
	if len(hash) > orderBytes {
		hash = hash[:orderBytes]
	}

	ret := new(big.Int).SetBytes(hash)
	excess := len(hash)*8 - orderBits
	if excess > 0 {
		ret.Rsh(ret, uint(excess))
	}
	return ret
}

func GetAesKey(sk tcrypto.PrivKey) ([]byte, error) {
	hashedSk, err := MsgToHashString(sk.Bytes())
	if err != nil {
		return nil, err
	}
	hashedSkByte, err := hex.DecodeString(hashedSk)
	if err != nil {
		return nil, err
	}
	derivedKey := pbkdf2.Key(hashedSkByte, []byte("thorchain"), 262144, 32, sha256.New)
	encryptKey := derivedKey[:32]
	return encryptKey, nil
}

func padding(cipherText []byte) []byte {
	padding := aes.BlockSize - len(cipherText)%aes.BlockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func unPadding(plantText []byte) ([]byte, error) {
	if len(plantText) == 0 {
		return nil, errors.New("invalid message for unpadding")
	}
	length := len(plantText)
	unPadding := int(plantText[length-1])
	if length-unPadding < 1 {
		return nil, errors.New("invalid message for unpadding")
	}
	return plantText[:(length - unPadding)], nil
}

func AesEncryption(key, data []byte) ([]byte, error) {
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plainText := padding(data)
	cipherText := make([]byte, aes.BlockSize+len(plainText))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	aesGcm := cipher.NewCBCEncrypter(aesBlock, iv)
	aesGcm.CryptBlocks(cipherText[aes.BlockSize:], plainText)
	return cipherText, nil
}

func AesDecryption(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext to short")
	}
	iv := data[:aes.BlockSize]
	aesGcm := cipher.NewCBCDecrypter(block, iv)
	plainText := make([]byte, len(data)-aes.BlockSize)
	cipherText := data[aes.BlockSize:]
	aesGcm.CryptBlocks(plainText, cipherText)
	ret, err := unPadding(plainText)
	return ret, err
}
