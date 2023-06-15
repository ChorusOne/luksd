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
)

const (
	server = "http://192.168.122.173:3000"
	device = "/dev/vdb1"
)

type keyResponse struct {
	Key string `json:"key"`
	Header string `json:"header"`
}

func main() {
	encryptDevice(device, "chorus")
	registerClient("./hdr.img", "/tmp/luks.key")
	// ❯ curl 192.168.122.173:3000/admin/approve -d 192.168.122.1 -v
	decryptDevice(device)
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
	url := fmt.Sprintf("%s/machine/key", server)

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
	url := fmt.Sprintf("%s/machine/register", server)

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

	data := fmt.Sprintf("{\"header\": \"%s\", \"key\": \"%s\"}", base64Header, base64Key)
	jsonData := []byte(data)

	request, error := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
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