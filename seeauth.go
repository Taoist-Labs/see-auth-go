package seeauth

import (
	"errors"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spruceid/siwe-go"
)

//type WalletType string
//type WalletVendor string
//
//const (
//	WalletTypeEOA WalletType = "EOA"
//	WalletTypeAA  WalletType = "AA"
//)
//
//const (
//	WalletVendorMetamask WalletVendor = "metamask"
//	WalletVendorJoyid    WalletVendor = "joyid"
//	WalletVendorUnipass  WalletVendor = "unipass"
//)

type SeeAuth struct {
	Address      string `json:"address"` // user wallet, seedao wallet is solid in sdk
	Nonce        string `json:"nonce"`   // user nonce, seedao nonce is `SignatureC`
	WalletType   string `json:"wallet_type"`
	WalletVendor string `json:"wallet_vendor"`
	Domain       string `json:"domain"`
	MessageC     string `json:"message_c"`
	MessageS     string `json:"message_s"`
	SignatureC   string `json:"signature_c"`
	SignatureS   string `json:"signature_s"`
}

const sAddress = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"

func VerifyWithMemoryCache() {
	// TODO implements this
}

func Verify(auth *SeeAuth) error {
	// verify seedao signature
	if err := verifyEOA(sAddress, auth.MessageS, auth.Domain, auth.SignatureC[10:26], auth.SignatureS); err != nil {
		return err
	}

	// verify user signature
	if err := verifyEOA(auth.Address, auth.MessageC, auth.Domain, auth.Nonce, auth.SignatureC); err != nil {
		return err
	}

	return nil
}

func verifyEOA(address, message, domain, nonce, signature string) error {
	m, err := siwe.ParseMessage(message)
	if err != nil {
		return err
	}

	publicKey, err := m.Verify(signature, &domain, &nonce, nil)
	if err != nil {
		return err
	}

	if crypto.PubkeyToAddress(*publicKey).Hex() != address {
		return errors.New("invalid signature")
	}

	return nil
}

func verifyUnipass(wallet, message, domain, nonce, signature string) error {
	// TODO implements this
	return nil
}
