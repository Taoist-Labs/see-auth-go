package seeauth

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Taoist-Labs/see-auth-go/proof"
	"github.com/Taoist-Labs/see-auth-go/signature"
)

func TestFlow(t *testing.T) {
	privateKey := "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	wallet := "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	recipient := "0x0000000000000000000000000000000000000000"

	nonce := GenerateNonce()

	message, sig, err := signature.Sign(nonce, 60*time.Second, privateKey)
	if err != nil {
		t.Errorf("signature.Sign() error = %v", err)
		return
	}

	seeAuth, err := Auth(&SignatureParams{
		WalletName: WalletNameMetamask,
		Wallet:     wallet,
		Nonce:      nonce,
		Message:    message,
		Signature:  sig,
	}, &ProofParams{
		Recipient: recipient,
		Schema: &proof.SchemaData{
			Wallet: wallet,
			Vendor: "os+",
		},
		PrivateKey: privateKey,
	})
	if err != nil {
		t.Errorf("Auth() error = %v", err)
		return
	}

	//t.Logf("seeAuth = %+v", seeAuth)
	//t.Logf("seeAuth = %+v", seeAuth.Signature)
	//t.Logf("seeAuth = %+v", seeAuth.Proof)

	j, _ := json.Marshal(seeAuth)
	//t.Logf("seeAuth JSON = %s", string(j))

	var p proof.Proof
	_ = json.Unmarshal([]byte(seeAuth.Proof.Proof), &p)
	t.Logf("Proof Message = %v", p.Sig.Message)
	t.Logf("Proof Signature = %+v", p.Sig.Signature)

	var seeAuth2 SeeAuth
	_ = json.Unmarshal(j, &seeAuth2)

	w, err := SeeDAOAuth(recipient, &seeAuth2)
	if err != nil {
		t.Errorf("SeeDAOAuth() error = %v", err)
		return
	}

	if w != wallet {
		t.Errorf("SeeDAOAuth() wallet = %v", w)
		return
	}
}
