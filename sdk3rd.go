package seeauth

import (
	"errors"

	"github.com/Taoist-Labs/see-auth-go/proof"
	"github.com/Taoist-Labs/see-auth-go/signature"
)

func SeeDAOAuth(recipient string, seeAuth *SeeAuth) (string, error) {
	// ---> get proof-used-flag from cache

	// proofing proof
	ok, schemaData, err := proof.Verify(attester, recipient, seeAuth.Proof.Proof)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("Invalid proof")
	}

	// ---> set proof-used-flag from cache

	// verify signature
	err = signature.Verify(seeAuth.Wallet, seeAuth.Signature.Nonce, seeAuth.Signature.Message, seeAuth.Signature.Signature)
	if err != nil {
		return "", errors.New("Invalid signature")
	}

	if schemaData.Wallet != seeAuth.Wallet {
		return "", errors.New("Invalid payload")
	}

	return seeAuth.Wallet, nil
}
