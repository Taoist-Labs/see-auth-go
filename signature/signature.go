package signature

import (
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spruceid/siwe-go"
)

var (
	chainId = 1
	version = "1"

	domain    = "app.seedao.xyz"
	uri       = "https://app.seedao.xyz"
	statement = "Welcome to SeeDAO!"
)

func Sign(nonce string, signatureLifetime time.Duration, privateKey string) (message, signature string, err error) {
	key, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		return
	}
	address := crypto.PubkeyToAddress(key.PublicKey).Hex()

	options := map[string]interface{}{
		"statement":      statement,
		"chainId":        chainId,
		"version":        version,
		"issuedAt":       time.Now().UTC().Format(time.RFC3339),
		"expirationTime": time.Now().UTC().Add(signatureLifetime).Format(time.RFC3339),
	}
	m, err := siwe.InitMessage(domain, address, uri, nonce, options)
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

func Verify(wallet, nonce, message, signature string) error {
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
