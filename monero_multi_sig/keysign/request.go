package keysign

// Request request to sign a message
type Request struct {
	PoolPubKey    string   `json:"pool_pub_key"` // pub key of the pool that we would like to send this message from
	Message       string   `json:"message"`      // base64 encoded message to be signed
	SignerPubKeys []string `json:"signer_pub_keys"`
	BlockHeight   int64    `json:"block_height"`
	Version       string   `json:"tss_version"`
	// these parameters are for monero
	RpcAddress string `json:"rpc_address"`
	EncodedTx  string `json:"encoded_transaction"`
}

func NewRequest(pk, msg string, blockHeight int64, signers []string, version, rpCAddress, encodedTx string) Request {
	return Request{
		PoolPubKey:    pk,
		Message:       msg,
		SignerPubKeys: signers,
		BlockHeight:   blockHeight,
		Version:       version,
		RpcAddress:    rpCAddress,
		EncodedTx:     encodedTx,
	}
}
