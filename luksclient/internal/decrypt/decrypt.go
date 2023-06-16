package decrypt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"io"

	"google.golang.org/protobuf/reflect/protoreflect"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/ChorusOne/luksclient/types"
)

func getKey() types.keyResponse {
	url := fmt.Sprintf("%s/machine/key", types.serverURL)

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

	res := types.keyResponse{}
	json.Unmarshal(b, &res)
	if res == (types.keyResponse{}) {
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

func decryptDeviceTPM() {
	tpmBase64 := createTPM()

	quoteData := quoteMessage{
		Nonce: "nonce",
		Mode: modeType{
			Tpm: tpmType{
				PubKey: tpmBase64.pubKey,
				EventLog: "eventLog",
				Quote1: Quote{
					Msg: tpmBase64.quote,
					Sig: tpmBase64.sig,
					Pcr: tpmBase64.pcrs,
				},
				Quote256: Quote{
					Msg: tpmBase64.quote,
					Sig: tpmBase64.sig,
					Pcr: tpmBase64.pcrs,
				},
				Quote384: Quote{
					Msg: tpmBase64.quote,
					Sig: tpmBase64.sig,
					Pcr: tpmBase64.pcrs,
				},
			},
		},
	}

	quoteDataJSON, err := json.Marshal(quoteData)
	if err != nil {
		panic(err)
	}

	resp, err := http.Post(serverURL + "/machine/key", "application/json", bytes.NewBuffer(quoteDataJSON))
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



func decryptDevice(encryptDevice string) {
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