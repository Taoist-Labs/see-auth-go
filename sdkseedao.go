package seeauth

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/Taoist-Labs/see-auth-go/common"
	"github.com/Taoist-Labs/see-auth-go/proof"
	"github.com/Taoist-Labs/see-auth-go/signature"
	"github.com/spruceid/siwe-go"
)

func GenerateNonce() string {
	nonce := siwe.GenerateNonce()
	number, _ := common.GetLatestBlockNumber() // when something wrong, `number` is 0
	return fmt.Sprintf("%s%d", nonce, number)
}

type (
	SignatureParams struct {
		WalletName WalletName
		Wallet     string
		Domain     string
		Nonce      string
		Message    string
		Signature  string
	}
	ProofParams struct {
		Recipient  string
		Schema     *proof.SchemaData
		PrivateKey string
	}
)

func Auth(signatureParams *SignatureParams, proofParams *ProofParams) (*SeeAuth, error) {
	// verify latest-block-number
	number, _ := strconv.Atoi(signatureParams.Nonce[16:])
	numberOnChain, _ := common.GetLatestBlockNumber()
	if number != 0 && numberOnChain != 0 && int(numberOnChain)-number > 5 {
		return nil, errors.New("block number too old")
	}

	// verify signature
	err := signature.Verify(signatureParams.Wallet, signatureParams.Domain, signatureParams.Nonce, signatureParams.Message, signatureParams.Signature)
	if err != nil {
		return nil, err
	}

	// generating proof
	p, err := proof.Sign(proofParams.Recipient, proofLifetime, proofParams.Schema, proofParams.PrivateKey)
	if err != nil {
		return nil, err
	}

	return &SeeAuth{
		Wallet:     signatureParams.Wallet,
		WalletName: signatureParams.WalletName,
		Signature: &Signature{
			Domain:    signatureParams.Domain,
			Nonce:     signatureParams.Nonce,
			Message:   signatureParams.Message,
			Signature: signatureParams.Signature,
		},
		Proof: &Proof{
			Proof: p,
		},
	}, nil
}
