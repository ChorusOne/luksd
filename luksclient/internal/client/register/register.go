package register

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
	"strings"
	"crypto/rand"
	"io"

	"google.golang.org/protobuf/reflect/protoreflect"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/ChorusOne/luksclient/types"
)

func createTPM() types.TPMBase64 {
	tpmWrite, err := tpmutil.OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Println(err)
	}

	defer tpmWrite.Close()

	ak,err := client.AttestationKeyECC(tpmWrite)
	if err != nil {
		log.Fatalf("failed to create endorsement key: %v", err)
	}

	defer ak.Close()

	nonce := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatalf("failed to create nonce: %v", err)
	}

	pubKey := ak.CertDERBytes()
	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKey)


	pcr7 := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,23},
	}

	quote, err := ak.Quote(pcr7, nonce)
	if err != nil {
		log.Fatalf("failed to create quote: %v", err)
	}

	// On verifier, verify the quote against a stored public key/AK
	// certificate's public part and the nonce passed.
	quoteBase64 := base64.StdEncoding.EncodeToString(quote.GetQuote())
	pcrsBase64 := base64.StdEncoding.EncodeToString([]byte(quote.GetPcrs().String()))
	sigBase64 := base64.StdEncoding.EncodeToString(quote.GetRawSig())

	return types.TPMBase64{quoteBase64, pcrsBase64, sigBase64, pubKeyBase64}
	// err = os.WriteFile("/tmp/quote", []byte(quoteBase64), 0644)
	// if err != nil {
	// 	panic(err)
	// }

	// err = os.WriteFile("/tmp/pcrs", []byte(pcrsBase64), 0644)
	// if err != nil {
	// 	panic(err)
	// }

	// err = os.WriteFile("/tmp/sig", []byte(sigBase64), 0644)
	// if err != nil {
	// 	panic(err)
	// }


}




func registerClientTPM(h string, k string) {

	tpmBase64 := createTPM()

	header, err := os.ReadFile(h)
	if err != nil {
		log.Fatal(err)
	}

	// headerClean := removeControlCharacters(string(header))
	headerClean := strings.TrimSpace(string(header))
	base64Header := base64.StdEncoding.EncodeToString([]byte(headerClean))

	key, err := os.ReadFile(k)
	if err != nil {
		log.Fatal(err)
	}

	// keyClean := removeControlCharacters(string(key))
	keyClean := strings.TrimSpace(string(key))
	base64Key := base64.StdEncoding.EncodeToString([]byte(keyClean))

	quoteData := types.quoteMessage{
		Header: base64Header,
		Key: base64Key,
		Mode: types.modeType{
			Tpm: types.tpmType{
				PubKey: tpmBase64.pubKey,
				EventLog: "eventLog",
				Quote1: types.Quote{
					Msg: tpmBase64.quote,
					Sig: tpmBase64.sig,
					Pcr: tpmBase64.pcrs,
				},
				Quote256: types.Quote{
					Msg: tpmBase64.quote,
					Sig: tpmBase64.sig,
					Pcr: tpmBase64.pcrs,
				},
				Quote384: types.Quote{
					Msg: tpmBase64.quote,
					Sig: tpmBase64.sig,
					Pcr: tpmBase64.pcrs,
				},
			},
		},
	}

	jsonData, err := json.Marshal(quoteData)
	if err != nil {
		panic(err)
	}

	url := fmt.Sprintf("%s/machine/register", types.serverURL)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		panic(err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	fmt.Println("Response Status:", resp.Status)
	fmt.Println("Response Headers:", resp.Header)
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Response Body:", string(body))
	// msg := quote.ProtoReflect()

	// // Print the message descriptor
	// printMessageDescriptor(msg.Descriptor())
}




func createEmtpyDevice(device string) error {
	deviceSize := 100 * 1024 * 1024 // 100 megabytes

	// Write null bytes to the file
	nullBytes := make([]byte, deviceSize)
	err := ioutil.WriteFile(device, nullBytes, 0644)
	if err != nil {
		fmt.Println("Error writing to device:", err)
		return err
	}

	return nil
}

func encryptDevice(encryptDevice string, password string) {
	err := os.WriteFile("/tmp/luks.key", []byte(password), 0644)
	if err != nil {
		log.Fatal(err)
	}

	if _, err := os.Stat(encryptDevice); os.IsNotExist(err) {
		err := createEmtpyDevice(encryptDevice)
		if err != nil {
			log.Fatal(err)
		}
	}

	cmd := exec.Command("sh", "-c", fmt.Sprintf("cryptsetup luksFormat %s --header hdr.img -q -v < /tmp/luks.key", encryptDevice))
	fmt.Print("Encrypting file...")
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
}


func registerClient(h string, k string) {
	url := fmt.Sprintf("%s/machine/register", types.serverURL)

	header, err := os.ReadFile(h)
	if err != nil {
		log.Fatal(err)
	}

	// headerClean := removeControlCharacters(string(header))
	headerClean := strings.TrimSpace(string(header))
	base64Header := base64.StdEncoding.EncodeToString([]byte(headerClean))

	key, err := os.ReadFile(k)
	if err != nil {
		log.Fatal(err)
	}

	// keyClean := removeControlCharacters(string(key))
	keyClean := strings.TrimSpace(string(key))
	base64Key := base64.StdEncoding.EncodeToString([]byte(keyClean))
	pubKey := "random"
	pubKeyBase64 := base64.StdEncoding.EncodeToString([]byte(pubKey))
	// data := fmt.Sprintf("{\"header\": \"%s\", \"key\": \"%s\"}", base64Header, base64Key)
	// jsonData := []byte(data)

	jsonData := types.quoteMessageDisk{
		Header: base64Header,
		Key: base64Key,
		Mode: types.modeTypeDisk{
			Disk: types.diskType{
				PubKey: pubKeyBase64,
				EventLog: "eventLog",
			},
		},
	}

	jd, err := json.Marshal(jsonData)
	if err != nil {
		log.Fatal(err)
	}

	request, error := http.NewRequest("POST", url, bytes.NewBuffer(jd))
	request.Header.Set("Content-Type", "application/json; charset=utf-8")

	client := &http.Client{}

	fmt.Println("Registering client...")
	fmt.Printf("Waiting for admin approval: curl %s/admin/approve -d {IP}\n", url)

	response, error := client.Do(request)
	if error != nil {
		panic(error)
	}

	defer response.Body.Close()

	fmt.Println("response Status:", response.Status)
	fmt.Println("response Headers:", response.Header)
	body, _ := ioutil.ReadAll(response.Body)
	fmt.Println("response Body:", string(body))
}


func removeControlCharacters(input string) string {
	var result strings.Builder

	for _, r := range input {
		if r >= ' ' {
			result.WriteRune(r)
		}
	}

	return result.String()
}
