package offchain

import (
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

var (
	privateKey, _ = crypto.HexToECDSA("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	attester      = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	recipient     = "0x0000000000000000000000000000000000000000"

	primaryType = "Attest"
	types       = apitypes.Types{
		"EIP712Domain": []apitypes.Type{
			{Name: "name", Type: "string"},
			{Name: "version", Type: "string"},
			{Name: "chainId", Type: "uint256"},
			{Name: "verifyingContract", Type: "address"},
		},
		"Attest": []apitypes.Type{
			{Name: "version", Type: "uint16"},
			{Name: "nonce", Type: "string"},
			{Name: "schema", Type: "bytes32"},
			{Name: "recipient", Type: "address"},
			{Name: "time", Type: "uint64"},
			{Name: "expirationTime", Type: "uint64"},
			{Name: "revocable", Type: "bool"},
			{Name: "refUID", Type: "bytes32"},
			{Name: "data", Type: "bytes"},
		},
	}
	typedDataDomain = apitypes.TypedDataDomain{
		Name:              "EAS Attestation",
		Version:           "1.2.0",
		ChainId:           math.NewHexOrDecimal256(80001),
		VerifyingContract: "0xaEF4103A04090071165F78D45D83A0C0782c2B2a",
	}
	typedDataMessage = apitypes.TypedDataMessage{
		"recipient":      recipient,
		"time":           "1704126921", // Unix timestamp of current time
		"expirationTime": "1704126981", // Unix timestamp of when attestation expires. (0 for no expiration)
		"revocable":      true,         // Be aware that if your schema is not revocable, this MUST be false
		"version":        "1",
		"nonce":          "1",
		"schema":         "0x32275eb98dcb8f82848adef9fa52311cc9e83bc6fdb34c5f46ac4b8d957ad3d9",
		"refUID":         "0x0000000000000000000000000000000000000000000000000000000000000000",
		"data":           "0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000036f732b0000000000000000000000000000000000000000000000000000000000",
	}
)

func TestSignOffChainAttestation(t *testing.T) {
	type args struct {
		typedData *apitypes.TypedData
	}
	tests := []struct {
		name string
		args args
		//want    *Sig
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				typedData: &apitypes.TypedData{
					Types:       types,
					PrimaryType: primaryType,
					Domain:      typedDataDomain,
					Message:     typedDataMessage,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SignOffChainAttestation(privateKey, tt.args.typedData)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignOffChainAttestation() error = %v, wantErr = %v", err, tt.wantErr)
				return
			}
			//if !reflect.DeepEqual(got, tt.want) {
			//	t.Errorf("SignOffChainAttestation() got = %v, want = %v", got, tt.want)
			//}
			if err == nil {
				t.Logf("%+v", got)
			}
		})
	}
}

func TestVerifyOffChainAttestation(t *testing.T) {
	type args struct {
		attester        string
		recipient       string
		typedData       *apitypes.TypedData
		expectTypedData *apitypes.TypedData
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				attester:  attester,
				recipient: recipient,
				typedData: &apitypes.TypedData{
					Types:       types,
					PrimaryType: primaryType,
					Domain:      typedDataDomain,
					Message: apitypes.TypedDataMessage{
						"recipient":      recipient,
						"time":           fmt.Sprintf("%d", time.Now().UTC().Unix()),                     // Unix timestamp of current time
						"expirationTime": fmt.Sprintf("%d", time.Now().UTC().Add(60*time.Second).Unix()), // Unix timestamp of when attestation expires. (0 for no expiration)
						"revocable":      true,                                                           // Be aware that if your schema is not revocable, this MUST be false
						"version":        "1",
						"nonce":          "0",
						"schema":         schemaUID,
						"refUID":         typedDataMessage["refUID"],
						"data":           typedDataMessage["data"],
					},
				},
				expectTypedData: &apitypes.TypedData{
					Types:       types,
					PrimaryType: primaryType,
					Domain:      typedDataDomain,
				},
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "proof expired",
			args: args{
				attester:  attester,
				recipient: recipient,
				typedData: &apitypes.TypedData{
					Types:       types,
					PrimaryType: primaryType,
					Domain:      typedDataDomain,
					Message:     typedDataMessage,
				},
				expectTypedData: &apitypes.TypedData{
					Types:       types,
					PrimaryType: primaryType,
					Domain:      typedDataDomain,
				},
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "proof tttt",
			args: args{
				attester:  attester,
				recipient: recipient,
				typedData: &apitypes.TypedData{
					Types:       types,
					PrimaryType: primaryType,
					Domain:      typedDataDomain,
					Message: apitypes.TypedDataMessage{
						"recipient":      "0x0000000000000000000000000000000000000000",
						"time":           "1704249694", // Unix timestamp of current time
						"expirationTime": "1704251294", // Unix timestamp of when attestation expires. (0 for no expiration)
						"revocable":      true,         // Be aware that if your schema is not revocable, this MUST be false
						"version":        "1",
						"nonce":          "0",
						"schema":         "0x32275eb98dcb8f82848adef9fa52311cc9e83bc6fdb34c5f46ac4b8d957ad3d9",
						"refUID":         "0x0000000000000000000000000000000000000000000000000000000000000000",
						"data":           "0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000036f732b0000000000000000000000000000000000000000000000000000000000",
					},
				},
				expectTypedData: &apitypes.TypedData{
					Types:       types,
					PrimaryType: primaryType,
					Domain:      typedDataDomain,
				},
			},
			want:    true,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := SignOffChainAttestation(privateKey, tt.args.typedData)
			if err != nil {
				t.Errorf("SignOffChainAttestation() error = %v", err)
				return
			}
			t.Logf("Proof Message = %v", tt.args.typedData.Message)
			t.Logf("Proof Signature: %+v", sig.Signature)

			got, err := VerifyOffChainAttestation(tt.args.attester, tt.args.recipient, tt.args.expectTypedData, sig)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyOffChainAttestation() error = %v, wantErr = %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("VerifyOffChainAttestation() got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func Test_getOffChainUID(t *testing.T) {
	type args struct {
		version        uint16
		schema         string
		recipient      string
		time           uint64
		expirationTime uint64
		revocable      bool
		refUID         string
		data           string
	}
	tests := []struct {
		name string
		args apitypes.TypedDataMessage
		want string
	}{
		{
			name: "ok",
			args: apitypes.TypedDataMessage{
				"version":        "1",
				"schema":         "0x32275eb98dcb8f82848adef9fa52311cc9e83bc6fdb34c5f46ac4b8d957ad3d9",
				"recipient":      "0x0000000000000000000000000000000000000000",
				"time":           "1703962538",
				"expirationTime": "1703962537",
				"revocable":      true,
				"refUID":         "0x0000000000000000000000000000000000000000000000000000000000000000",
				"data":           "0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000036f732b0000000000000000000000000000000000000000000000000000000000",
			},
			want: "0x27600687657c97bcdd6d137c62e727c805ac563b94fdc08b1ffe9d15cbd6f55d",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getOffChainUID(tt.args); got != tt.want {
				t.Errorf("getOffChainUID() = %v, want = %v", got, tt.want)
			}
		})
	}
}
