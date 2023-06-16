package utils

import (
	"encoding/base64"
	"fmt"
	"log"
	"crypto/rand"
	"io"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/ChorusOne/luksclient/internal/types"
)

func CreateTPM() types.TPMBase64 {
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

	return types.TPMBase64{Quote: quoteBase64, Pcrs: pcrsBase64,Sig: sigBase64,PubKey: pubKeyBase64}
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