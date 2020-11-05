package messages

type Algo int

const (
	KEYGEN1         = "KGRound1Message"
	KEYGEN2aUnicast = "KGRound2Message1"
	KEYGEN2b        = "KGRound2Message2"
	KEYGEN3         = "KGRound3Message"
	EDDSAKEYGEN1    = "EDDSAKGRound1Message"
	EDDSAKEYGEN2a   = "EDDSAKGRound2Message1"
	EDDSAKEYGEN2b   = "EDDSAKGRound2Message2"
	ECGDSAKEYGEN1   = "ECGDSAKGRound1Message"
	ECGDSAKEYGEN2a  = "ECGDSAKGRound2Message1"
	ECGDSAKEYGEN2b  = "ECGDSAKGRound2Message2"

	KEYSIGN1aUnicast = "SignRound1Message1"
	KEYSIGN1b        = "SignRound1Message2"
	KEYSIGN2Unicast  = "SignRound2Message"
	KEYSIGN3         = "SignRound3Message"
	KEYSIGN4         = "SignRound4Message"
	KEYSIGN5         = "SignRound5Message"
	KEYSIGN6         = "SignRound6Message"
	KEYSIGN7         = "SignRound7Message"
	KEYSIGN8         = "SignRound8Message"
	KEYSIGN9         = "SignRound9Message"
	EDDSAKEYSIGN1    = "EDDSASignRound1Message"
	EDDSAKEYSIGN2    = "EDDSASignRound2Message"
	EDDSAKEYSIGN3    = "EDDSASignRound3Message"
	EDDSAKEYSIGN4    = "EDDSASignRound4Message"
	EDDSAKEYSIGN5    = "EDDSASignRound5Message"
	EDDSAKEYSIGN6    = "EDDSASignRound6Message"
	EDDSAKEYSIGN7    = "EDDSASignRound7Message"
	ECGDSAKEYSIGN1   = "ECGDSASignRound1Message"
	ECGDSAKEYSIGN2   = "ECGDSASignRound2Message"
	ECGDSAKEYSIGN3   = "ECGDSASignRound3Message"
	ECGDSAKEYSIGN4   = "ECGDSASignRound4Message"
	ECGDSAKEYSIGN5   = "ECGDSASignRound5Message"
	ECGDSAKEYSIGN6   = "ECGDSASignRound6Message"
	ECGDSAKEYSIGN7   = "ECGDSASignRound7Message"

	ECDSATSSKEYGENROUNDS  = 4
	ECDSATSSKEYSIGNROUNDS = 10

	EDDSATSSKEYGENROUNDS  = 3
	EDDSATSSKEYSIGNROUNDS = 8

	ECGDSATSSKEYGENROUNDS  = 3
	ECGDSATSSKEYSIGNROUNDS = 8

	ECDSAKEYGEN Algo = iota
	ECDSAKEYSIGN
	EDDSAKEYGEN
	EDDSAKEYSIGN
	ECGDSAKEYGEN
	ECGDSAKEYSIGN
)
