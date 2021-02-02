package keysign

// Request request to sign a message
type Request struct {
	SignerPubKeys []string `json:"signer_pub_keys"`
	BlockHeight   int64    `json:"block_height"`
	Version       string   `json:"tss_version"`
	// these parameters are for monero
	RpcAddress string `json:"rpc_address"`
	EncodedTx  string `json:"encoded_transaction"`
}

func NewRequest(blockHeight int64, signers []string, version, rpCAddress, encodedTx string) Request {
	return Request{
		SignerPubKeys: signers,
		BlockHeight:   blockHeight,
		Version:       version,
		RpcAddress:    rpCAddress,
		EncodedTx:     encodedTx,
	}
}
