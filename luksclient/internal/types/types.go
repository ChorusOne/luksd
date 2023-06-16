package types

const (
	ServerURL = "http://192.168.122.173:3000"
	Device    = "/dev/vdb1"
)

type KeyReponse struct {
	Key    string `json:"key"`
	Header string `json:"header"`
}

type QuoteMessageDisk struct {
	Mode   ModeTypeDisk `json:"mode"`
	Header string       `json:"header"`
	Key    string       `json:"key"`
}

type QuoteMessage struct {
	Nonce  string   `json:"nonce"`
	Mode   ModeType `json:"mode"`
	Header string   `json:"header"`
	Key    string   `json:"key"`
}

type ModeType struct {
	Tpm TPMType `json:"Tpm"`
}

type ModeTypeDisk struct {
	Disk DiskType `json:"Disk"`
}

type DiskType struct {
	PubKey   string `json:"pubkey"`
	EventLog string `json:"eventlog"`
}

type TPMType struct {
	PubKey   string `json:"pubkey"`
	EventLog string `json:"eventlog"`
	Quote1   Quote  `json:"quote1"`
	Quote256 Quote  `json:"quote256"`
	Quote384 Quote  `json:"quote384"`
}

type Quote struct {
	Msg string `json:"msg"`
	Sig string `json:"sig"`
	Pcr string `json:"pcr"`
}

type TPMBase64 struct {
	Quote  string
	Pcrs   string
	Sig    string
	PubKey string
}