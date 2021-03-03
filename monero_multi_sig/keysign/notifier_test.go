package keysign

import (
	"fmt"

	moneroWallet "gitlab.com/thorchain/tss/monero-wallet-rpc/wallet"
	. "gopkg.in/check.v1"

	"gitlab.com/thorchain/tss/go-tss/conversion"
)

type NotifierTestSuite struct{}

var (
	_                      = Suite(&NotifierTestSuite{})
	testEncodedTransaction = "eyJkZXN0aW5hdGlvbnMiOlt7ImFtb3VudCI6NTAwLCJhZGRyZXNzIjoiNDhRcDFEWVk5NXdGMkJOYmhRWkRkNUo4ZFpDdWNNUno5OVk0d0FVYURqUWhqWDhyb3lvd2ZvZzFzTjlXQWRWZXNoUXV2VTZxS0ZpOUppNGdqOVpSRWtqVEZZc1FiWlgifV0sImFjY291bnRfaW5kZXgiOjAsInN1YmFkZHJfaW5kaWNlcyI6bnVsbCwicHJpb3JpdHkiOjAsIm1peGluIjowLCJyaW5nX3NpemUiOjExLCJ1bmxvY2tfdGltZSI6MCwicGF5bWVudF9pZCI6IiIsImdldF90eF9rZXkiOnRydWUsImdldF90eF9oZXgiOnRydWUsImdldF90eF9tZXRhZGF0YSI6dHJ1ZX0="
)

func (*NotifierTestSuite) SetUpSuite(c *C) {
	conversion.SetupBech32Prefix()
}

func (NotifierTestSuite) TestNewNotifier(c *C) {
	config := moneroWallet.Config{
		Address: "fake",
	}
	dummyClient := moneroWallet.New(config)

	n, err := NewNotifier("", testEncodedTransaction, dummyClient, 0)
	c.Assert(err, NotNil)
	c.Assert(n, IsNil)
	n, err = NewNotifier("aasfdasdf", "", dummyClient, 0)
	c.Assert(err, NotNil)
	c.Assert(n, IsNil)

	n, err = NewNotifier("hello", "aaaa", dummyClient, 0)
	c.Assert(err, NotNil)
	c.Assert(n, IsNil)

	n, err = NewNotifier("hello", testEncodedTransaction, dummyClient, 0)
	c.Assert(err, IsNil)
	c.Assert(n, NotNil)
	ch := n.GetResponseChannel()
	c.Assert(ch, NotNil)
}

func (NotifierTestSuite) TestNotifierHappyPath(c *C) {
	rpcAddress := fmt.Sprintf("http://%s:18083/json_rpc", remoteAddress[0])
	rpcWalletConfig := moneroWallet.Config{
		Address: rpcAddress,
	}

	wallet := moneroWallet.New(rpcWalletConfig)

	walletName := "thorpub1addwnpepq2m5ng0e6vm66feecrwxp37cdvmezsysghskz3t5w2du4c48qwupxn96nrr.mo"
	passcode := "f754b5c0b920f5ec3e364b1bf30947dd8a84eccc5cf14bd07a6fd227d0d36f25"
	// now open the wallet
	walletOpenReq := moneroWallet.RequestOpenWallet{
		Filename: walletName,
		Password: passcode,
	}

	err := wallet.OpenWallet(&walletOpenReq)
	c.Assert(err, IsNil)

	n, err := NewNotifier("hello", testEncodedTransaction, wallet, 1)
	c.Assert(err, IsNil)
	c.Assert(n, NotNil)

	spendProof := MoneroSpendProof{
		TxKey:         "6283f00c65ddf91e3f28439f437abf983039284468fefaeaa16ecb6cd7492205",
		TransactionID: "b0e34162b46dffab9fbca34384c39b4020b254964257c78fe800dc652fde3a89",
	}

	// with a invalid signature, it should report the error of the invalid signature
	finish, err := n.ProcessSignature(&spendProof)
	c.Assert(err, NotNil)
	c.Assert(finish, Equals, false)

	spendProof.TransactionID = "549d0034f7799eecf7531d5311a3c8fee08eacc1fe964e791973a958d175b87a"
	finish, err = n.ProcessSignature(&spendProof)
	c.Assert(err, IsNil)
	c.Assert(finish, Equals, true)

	result := <-n.GetResponseChannel()
	c.Assert(result, NotNil)
	c.Assert(result.TransactionID, Equals, spendProof.TransactionID)
	c.Assert(result.TxKey, Equals, spendProof.TxKey)
}
