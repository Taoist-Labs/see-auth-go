package seeauth

import (
	"github.com/Taoist-Labs/see-auth-go/proof"
	"github.com/Taoist-Labs/see-auth-go/signature"
	"github.com/spruceid/siwe-go"
)

func GenerateNonce() string {
	return siwe.GenerateNonce()
}

type (
	SignatureParams struct {
		WalletName WalletName
		Wallet     string
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
	// verify signature
	err := signature.Verify(signatureParams.Wallet, signatureParams.Nonce, signatureParams.Message, signatureParams.Signature)
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
			Nonce:     signatureParams.Nonce,
			Message:   signatureParams.Message,
			Signature: signatureParams.Signature,
		},
		Proof: &Proof{
			Proof: p,
		},
	}, nil
}
