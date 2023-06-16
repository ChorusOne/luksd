package decrypt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"

	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/ChorusOne/luksclient/internal/types"
	"github.com/ChorusOne/luksclient/internal/utils"
)

func getKey() types.KeyReponse {

	nonceRes, err := http.Get(types.ServerURL + "/machine/nonce")
	if err != nil {
		panic(err)
	}

	defer nonceRes.Body.Close()

	nonceData, err := ioutil.ReadAll(nonceRes.Body)
	if err != nil {
		panic(err)
	}

	keyData := types.GetDiskData{
		Nonce: string(nonceData),
		Mode: types.Mode{
			Disk: types.DiskMode{
				NonceSignature: "",
			},
		},
	}

	quoteDataJSON, err := json.Marshal(keyData)
	if err != nil {
		panic(err)
	}

	resp, err := http.Post(types.ServerURL+"/machine/key", "application/json", bytes.NewBuffer(quoteDataJSON))
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	fmt.Println(resp.StatusCode)

	res := types.KeyReponse{}
	json.Unmarshal(body, &res)

	if res == (types.KeyReponse{}) {
		panic("Server didn't return key and header")
	}

	return res
}

func printMessageDescriptor(descriptor protoreflect.MessageDescriptor) {
	// Print the full name of the message
	fmt.Println("Message Full Name:", descriptor.FullName())

	// Print the fields of the message
	fmt.Println("Message Fields:")
	for i := 0; i < descriptor.Fields().Len(); i++ {
		field := descriptor.Fields().Get(i)
		fmt.Printf("Field %d: %s (%s)\n", i+1, field.Name(), field.FullName())
	}
}

func getKeyTPM() types.KeyReponse {
	fmt.Println("Decrypting device with TPM")

	tpmInfo := utils.GetTPM()

	nonceRes, err := http.Get(types.ServerURL + "/machine/nonce")
	if err != nil {
		panic(err)
	}

	defer nonceRes.Body.Close()

	nonceBody, err := ioutil.ReadAll(nonceRes.Body)
	if err != nil {
		panic(err)
	}

	quoteData := types.QuoteMessage{
		Nonce: string(nonceBody),
		Mode: types.ModeType{
			Tpm: types.TPMType{
				PubKey:   tpmInfo.PubKey,
				EventLog: "eventLog",
				Quote1: types.Quote{
					Msg: tpmInfo.Quote,
					Sig: tpmInfo.Sig,
					Pcr: tpmInfo.PCRs,
				},
				Quote256: types.Quote{
					Msg: tpmInfo.Quote,
					Sig: tpmInfo.Sig,
					Pcr: tpmInfo.PCRs,
				},
				Quote384: types.Quote{
					Msg: tpmInfo.Quote,
					Sig: tpmInfo.Sig,
					Pcr: tpmInfo.PCRs,
				},
			},
		},
	}

	quoteDataJSON, err := json.Marshal(quoteData)
	if err != nil {
		panic(err)
	}

	resp, err := http.Post(types.ServerURL+"/machine/key", "application/json", bytes.NewBuffer(quoteDataJSON))
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	fmt.Println(resp.StatusCode)
	fmt.Println(string(body))

	res := types.KeyReponse{}
	json.Unmarshal(body, &res)

	if res == (types.KeyReponse{}) {
		panic("Server didn't return key and header")
	}

	return res
}

func DecryptDevice(encryptedDevice string, method string) {
	var keyResponse types.KeyReponse

	if method == "disk" {
		keyResponse = getKey()
	} else if method == "tpm" {
		keyResponse = getKeyTPM()
	} else {
		panic("Invalid decription method can be tpm or disk")
	}

	key, err := base64.StdEncoding.DecodeString(keyResponse.Key)
	if err != nil {
		log.Fatal(err)
	}

	header, err := base64.StdEncoding.DecodeString(keyResponse.Header)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile("/luks.key", key, 0644)
	if err != nil {
		log.Fatal(err)
	}

	err = os.WriteFile("/hdr.img", header, 0644)
	if err != nil {
		log.Fatal(err)
	}

	decrypt(encryptedDevice)
}

func decrypt(encryptedDevice string) {

	fmt.Println("Decrypting device...")

	cmd := exec.Command("sh", "-c", fmt.Sprintf("cryptsetup open %s --key-file /luks.key --header /hdr.img -q -v chorus", encryptDevice))
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Decrypted Device")
}
