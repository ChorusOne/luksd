package types


const (
	serverURL = "http://192.168.122.173:3000"
	device = "/dev/vdb1"
)


type KeyReponse struct {
	Key string `json:"key"`
	Header string `json:"header"`
}

type quoteMessageDisk struct {
	Mode modeTypeDisk `json:"mode"`
	Header string `json:"header"`
	Key string `json:"key"`
}

type quoteMessage struct {
	Nonce string `json:"nonce"`
	Mode modeType `json:"mode"`
	Header string `json:"header"`
	Key string `json:"key"`
}

type modeType struct {
	Tpm tpmType `json:"Tpm"`
}

type modeTypeDisk struct {
	Disk diskType `json:"Disk"`
}

type diskType struct {
	PubKey string `json:"pubkey"`
	EventLog string `json:"eventlog"`
}

type tpmType struct {
	PubKey string `json:"pubkey"`
	EventLog string `json:"eventlog"`
	Quote1 Quote `json:"quote1"`
	Quote256 Quote `json:"quote256"`
	Quote384 Quote `json:"quote384"`
}

type Quote struct {
	Msg string `json:"msg"`
	Sig string `json:"sig"`
	Pcr string `json:"pcr"`
}

type TPMBase64 struct {
	quote string
	pcrs string
	sig string
	pubKey string
}