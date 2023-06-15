package main

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
)

const (
	serverURL = "http://192.168.122.173:3000"
	device = "/dev/vdb1"
)


type keyResponse struct {
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

func main() {
	// encryptDevice(device, "chorus")
	// registerClient("./tpm/hdr.img", "./tpm/password")
	// decryptDevice(device)
	// registerClientTPM("./tpm/hdr.img", "./tpm/password")
	decryptDeviceTPM()
}


func createTPM() TPMBase64 {
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

	return TPMBase64{quoteBase64, pcrsBase64, sigBase64, pubKeyBase64}
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

	quoteData := quoteMessage{
		Header: base64Header,
		Key: base64Key,
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

	jsonData, err := json.Marshal(quoteData)
	if err != nil {
		panic(err)
	}

	url := fmt.Sprintf("%s/machine/register", serverURL)
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

func getKey() keyResponse {
	url := fmt.Sprintf("%s/machine/key", serverURL)

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

	res := keyResponse{}
	json.Unmarshal(b, &res)
	if res == (keyResponse{}) {
		panic("Server didn't return key and header")
	}

	return res
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

func registerClient(h string, k string) {
	url := fmt.Sprintf("%s/machine/register", serverURL)

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

	jsonData := quoteMessageDisk{
		Header: base64Header,
		Key: base64Key,
		Mode: modeTypeDisk{
			Disk: diskType{
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
