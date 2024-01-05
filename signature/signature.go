package signature

import (
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spruceid/siwe-go"
)

// flowing constants are only used in `Sign` function
// and `Sign` function just for testing
var (
	tChainId = 1
	tVersion = "1"

	tDomain    = "app.seedao.xyz"
	tUri       = "https://app.seedao.xyz"
	tStatement = "Welcome to SeeDAO!"
)

// Sign !!~! just for testing ~~!!
func Sign(nonce string, signatureLifetime time.Duration, privateKey string) (message, signature string, err error) {
	key, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		return
	}
	address := crypto.PubkeyToAddress(key.PublicKey).Hex()

	options := map[string]interface{}{
		"statement":      tStatement,
		"chainId":        tChainId,
		"version":        tVersion,
		"issuedAt":       time.Now().UTC().Format(time.RFC3339),
		"expirationTime": time.Now().UTC().Add(signatureLifetime).Format(time.RFC3339),
	}
	m, err := siwe.InitMessage(tDomain, address, tUri, nonce, options)
	if err != nil {
		return
	}
	message = m.String()
	//fmt.Printf("~~~~message: %s\n", message)

	data := []byte(message)
	m1 := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	m2 := crypto.Keccak256Hash([]byte(m1))

	s, err := crypto.Sign(m2.Bytes(), key)
	if err != nil {
		return
	}
	s[64] += 27
	signature = fmt.Sprintf("0x%s", common.Bytes2Hex(s))
	//fmt.Printf("~~~~signature: %s\n", signature)

	return
}

func Verify(wallet, domain, nonce, message, signature string) error {
	m, err := siwe.ParseMessage(message)
	if err != nil {
		return err
	}

	publicKey, err := m.Verify(signature, &domain, &nonce, nil)
	if err != nil {
		return err
	}

	if crypto.PubkeyToAddress(*publicKey).Hex() != wallet {
		return errors.New("signer not match")
	}

	return nil
}
