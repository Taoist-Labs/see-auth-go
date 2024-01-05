package signature

import (
	"testing"
	"time"
)

const (
	privateKey        = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	wallet            = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	nonce             = "oNCEHm5jzQU2WvuBB"
	signatureLifetime = 10 * time.Second
)

func TestSign(t *testing.T) {
	type args struct {
		nonce             string
		privateKey        string
		signatureLifetime time.Duration
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				privateKey: privateKey,
			},
			wantErr: false,
		},
		{
			name: "error privateKey",
			args: args{
				privateKey: "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff88",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMessage, gotSignature, err := Sign(nonce, signatureLifetime, tt.args.privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr = %v", err, tt.wantErr)
				return
			}

			// print log
			if !tt.wantErr {
				t.Logf("Sign() gotMessage = %v, gotSignature = %v", gotMessage, gotSignature)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	type args struct {
		wallet            string
		signatureLifetime time.Duration
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				wallet:            wallet,
				signatureLifetime: signatureLifetime,
			},
			wantErr: false,
		},
		{
			name: "signer not match",
			args: args{
				wallet:            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92267",
				signatureLifetime: signatureLifetime,
			},
			wantErr: true,
		},
		{
			name: "signature expired",
			args: args{
				wallet:            wallet,
				signatureLifetime: -10 * time.Second,
			},
			wantErr: true,
		}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message, signature, _ := Sign(nonce, tt.args.signatureLifetime, privateKey)

			err := Verify(tt.args.wallet, tDomain, nonce, message, signature)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr = %v", err, tt.wantErr)
			}

			// print log
			if err != nil {
				t.Logf("Verify() error = %v", err)
			}
		})
	}
}
