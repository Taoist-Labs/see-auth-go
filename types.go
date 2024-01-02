package seeauth

type WalletName string

const (
	WalletNameMetamask WalletName = "metamask"
	WalletNameJoyid    WalletName = "joyid"
)

type SeeLogin struct {
	Wallet     string     `json:"wallet"`
	Message    string     `json:"message"`
	Signature  string     `json:"signature"`
	WalletName WalletName `json:"walletName"`
}

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
