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

	"github.com/ChorusOne/luksclient/internal/types"
	"github.com/ChorusOne/luksclient/internal/utils"
)

func RegisterClientTPM(h string, k string) {

	tpmBase64 := utils.CreateTPM()

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

	quoteData := types.QuoteMessage{
		Header: base64Header,
		Key:    base64Key,
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

	jsonData, err := json.Marshal(quoteData)
	if err != nil {
		panic(err)
	}

	url := fmt.Sprintf("%s/machine/register", types.ServerURL)
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

func RegisterClient(h string, k string) {
	url := fmt.Sprintf("%s/machine/register", types.ServerURL)

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

	jsonData := types.QuoteMessageDisk{
		Header: base64Header,
		Key:    base64Key,
		Mode: types.ModeTypeDisk{
			Disk: types.DiskType{
				PubKey:   pubKeyBase64,
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