package seeauth

type WalletName string

const (
	WalletNameMetamask WalletName = "metamask"
	WalletNameJoyid    WalletName = "joyid"
)

type (
	SeeAuth struct {
		Wallet     string     `json:"wallet"`
		WalletName WalletName `json:"walletName"`
		Signature  *Signature `json:"signature"`
		Proof      *Proof     `json:"proof"`
	}
	Signature struct {
		Nonce     string `json:"nonce"`
		Message   string `json:"message"`
		Signature string `json:"signature"`
	}
	Proof struct {
		Proof string `json:"proof"`
	}
)
