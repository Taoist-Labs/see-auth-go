package seeauth

import (
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spruceid/siwe-go"
)

func ExampleVerify() {
	seeAuth, err := signOfTwoWallets(10*time.Second, 10*time.Second)
	if err != nil {
		panic(err)
	}
	err = Verify(seeAuth)
	fmt.Printf("%+v", err)
	// Output: <nil>
}

func signOfTwoWallets(cLife, sLife time.Duration) (seeAuth *SeeAuth, err error) {
	cPrivateKey := "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	sPrivateKey := "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"

	cAddress := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

	domain := "app.seedao.xyz"
	uri := "https://app.seedao.xyz"

	// user sign
	nonce := siwe.GenerateNonce()
	cMessage, cSignature, err := sign(domain, uri, nonce, cPrivateKey, cLife)
	if err != nil {
		return
	}

	// seedao sign
	sMessage, sSignature, err := sign(domain, uri, cSignature[10:26], sPrivateKey, sLife)
	if err != nil {
		return
	}

	seeAuth = &SeeAuth{
		Address:      cAddress,
		Nonce:        nonce,
		WalletType:   "EOA",
		WalletVendor: "metamask",
		Domain:       domain,
		MessageC:     cMessage,
		MessageS:     sMessage,
		SignatureC:   cSignature,
		SignatureS:   sSignature,
	}

	return
}

func sign(domain, uri, nonce, privateKey string, life time.Duration) (message, signature string, err error) {
	key, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		return
	}
	address := crypto.PubkeyToAddress(key.PublicKey).Hex()

	options := map[string]interface{}{
		"statement":      "Welcome to SeeDAO!",
		"chainId":        1,
		"issuedAt":       time.Now().UTC().Format(time.RFC3339),
		"expirationTime": time.Now().UTC().Add(life).Format(time.RFC3339),
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
