package keygen

// Request request to do keygen
type Request struct {
	OldPartyKeys []string `json:"old_party_keys"`
	NewPartyKeys []string `json:"new_party_keys"`
	BlockHeight  int64    `json:"block_height"`
	Version      string   `json:"tss_version"`
}

// NewRequest create a new instance of keygen.Request
func NewRequest(oldPartyKeys, newPartyKeys []string, blockHeight int64, version string) Request {
	return Request{
		OldPartyKeys: oldPartyKeys,
		NewPartyKeys: newPartyKeys,
		BlockHeight:  blockHeight,
		Version:      version,
	}
}
