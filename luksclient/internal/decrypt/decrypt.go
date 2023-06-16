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
	url := fmt.Sprintf("%s/machine/key", types.ServerURL)

	fmt.Println("Getting header and key")
	fmt.Printf("Waiting for admin approval: curl %s/admin/approve -d {IP}\n", url)
	request, error := http.Get(url)
	if error != nil {
		panic(error)
	}

	defer request.Body.Close()

	b, err := ioutil.ReadAll(request.Body)
	if err != nil {
		panic(err)
	}

	res := types.KeyReponse{}
	json.Unmarshal(b, &res)
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

func DecryptDeviceTPM(encryptDevice string) {
	fmt.Println("Decrypting device with TPM")
	
	tpmBase64 := utils.CreateTPM()

	quoteData := types.QuoteMessage{
		Nonce: "nonce",
		Mode: types.ModeType{
			Tpm: types.TPMType{
				PubKey:   tpmBase64.PubKey,
				EventLog: "eventLog",
				Quote1: types.Quote{
					Msg: tpmBase64.Quote,
					Sig: tpmBase64.Sig,
					Pcr: tpmBase64.Pcrs,
				},
				Quote256: types.Quote{
					Msg: tpmBase64.Quote,
					Sig: tpmBase64.Sig,
					Pcr: tpmBase64.Pcrs,
				},
				Quote384: types.Quote{
					Msg: tpmBase64.Quote,
					Sig: tpmBase64.Sig,
					Pcr: tpmBase64.Pcrs,
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
}

func DecryptDevice(encryptDevice string) {
	keyResponse := getKey()

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

	fmt.Println("Decrypting device...")
	cmd := exec.Command("sh", "-c", fmt.Sprintf("cryptsetup open %s --key-file /luks.key --header /hdr.img -q -v chorus", encryptDevice))
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Decrypted Device")
}
