package checkquote

import (
	// "crypto"
	// "crypto/rand"
	"fmt"
	// "io"
	"io/ioutil"
	// "log"
	// "os"
	"strings"
	// "bufio"
	// "encoding/hex"
	// "scanner"
	"strconv"
	// "github.com/google/go-tpm-tools/client"
	// "github.com/google/go-tpm-tools/server"
	// "github.com/google/go-tpm-tools/proto/attest"
	// "github.com/google/go-tpm-tools/proto/tpm"
	// "github.com/google/go-tpm/tpmutil"
)

func Check() {
	// tpmWrite, err := tpmutil.OpenTPM("/dev/tpm0")
	// if err != nil {
	// 	fmt.Println(err)
	// }

	// defer tpmWrite.Close()

	// ak,err := client.AttestationKeyECC(tpmWrite)
	// if err != nil {
	// 	log.Fatalf("failed to create endorsement key: %v", err)
	// }

	// defer ak.Close()

	// nonce := make([]byte, 8)
	// if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
	// 	log.Fatalf("failed to create nonce: %v", err)
	// }

	// attestation, err := ak.Attest(client.AttestOpts{Nonce: nonce})
	// if err != nil {
	// 	log.Fatalf("failed to attest: %v", err)
	// }

	// akPub, err := os.ReadFile("./pubkeys/192.168.122.182")
	// if err != nil {
	// 	panic(err)
	// }

	file, err := ioutil.ReadFile("./pcrs/192.168.122.182_sha256.pcrs")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}

	line := string(file)

	pcrsMap := make(map[int32][]byte)

	// Extract key-value pairs from the line
	pairs := strings.Split(line, "  pcrs:{")
	for _, pair := range pairs[1:] {
		keyStart := strings.Index(pair, "key:") + 4
		keyEnd := strings.Index(pair, "  value:")
		keyStr := pair[keyStart:keyEnd]
		key, _ := strconv.ParseInt(keyStr, 10, 32)

		valueStart := strings.Index(pair, "value:\"") + 7
		valueEnd := strings.LastIndex(pair, "\"}")
		valueStr := pair[valueStart:valueEnd]
		valueBytes := []byte(valueStr)

		pcrsMap[int32(key)] = valueBytes
	}

	// Print the pcrsMap
	for key, value := range pcrsMap {
		fmt.Printf("Key: %d\nValue: %x\n\n", key, value)
	}

	// map[uint32][]byte
	// fmt.Println(akPub, quote)
	// attestation := attest.Attestation{
	// 	AkPub: akPub,
	// 	Quote: tpm.Quote{
	// 	Pcrs: &tpm.PCRs{
	// 		Hash: tpm.HashAlgo_SHA256,
	// 		Pcrs: ,
	// 	} ,
	// 	},
	// }
	// attestationState, err := server.VerifyAttestation(attestation, server.VerifyOpts{Nonce: nonce, TrustedAKs: []crypto.PublicKey{ak.PublicKey()}})
	// if err != nil {
	// 	// TODO: handle parsing or replay error.
	// 	log.Fatalf("failed to read PCRs: %v", err)
	// }
	// fmt.Println(attestationState.String())
}
