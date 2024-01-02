package offchain

import (
	"encoding/json"
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := SignOffChainAttestation(privateKey, tt.args.typedData)
			if err != nil {
				t.Errorf("SignOffChainAttestation() error = %v", err)
				return
			}
			s, _ := json.Marshal(sig.Signature)
			t.Logf("sig: %s", string(s))
			// offchain_test.go:170: sig: {"types":{"Attest":[{"name":"version","type":"uint16"},{"name":"nonce","type":"string"},{"name":"schema","type":"bytes32"},{"name":"recipient","type":"address"},{"name":"time","type":"uint64"},{"name":"expirationTime","type":"uint64"},{"name":"revocable","type":"bool"},{"name":"refUID","type":"bytes32"},{"name":"data","type":"bytes"}],"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}]},"primaryType":"Attest","domain":{"name":"EAS Attestation","version":"1.2.0","chainId":"0x13881","verifyingContract":"0xaEF4103A04090071165F78D45D83A0C0782c2B2a","salt":""},"message":{"data":"0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000036f732b0000000000000000000000000000000000000000000000000000000000","expirationTime":"1704163121","nonce":"0","recipient":"0x0000000000000000000000000000000000000000","refUID":"0x0000000000000000000000000000000000000000000000000000000000000000","revocable":true,"schema":"0x32275eb98dcb8f82848adef9fa52311cc9e83bc6fdb34c5f46ac4b8d957ad3d9","time":"1704163061","version":"1"},"signature":{"r":"0x74bc7fb764136a6427f541a15fc7e126791d3fef64d86208a58437012b6ee666","s":"0x6d120afaf26630f1f53ba03adfb6e428b03ade7b8eb69fe1a2396d9fe4699d65","v":27},"uid":"TODO..."
			// offchain_test.go:170: sig: {"types":{"Attest":[{"name":"version","type":"uint16"},{"name":"nonce","type":"string"},{"name":"schema","type":"bytes32"},{"name":"recipient","type":"address"},{"name":"time","type":"uint64"},{"name":"expirationTime","type":"uint64"},{"name":"revocable","type":"bool"},{"name":"refUID","type":"bytes32"},{"name":"data","type":"bytes"}],"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}]},"primaryType":"Attest","domain":{"name":"EAS Attestation","version":"1.2.0","chainId":"0x13881","verifyingContract":"0xaEF4103A04090071165F78D45D83A0C0782c2B2a","salt":""},"message":{"data":"0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000036f732b0000000000000000000000000000000000000000000000000000000000","expirationTime":"1704163157","nonce":"0","recipient":"0x0000000000000000000000000000000000000000","refUID":"0x0000000000000000000000000000000000000000000000000000000000000000","revocable":true,"schema":"0x32275eb98dcb8f82848adef9fa52311cc9e83bc6fdb34c5f46ac4b8d957ad3d9","time":"1704163097","version":"1"},"signature":{"r":"0x313669ffbc1e19d71164c1b9bbe4553ef5b2eef4b2e578daa4f5a9a3a41d8a0c","s":"0x69bb9e6262f60325a492c9e0c19e23beadcee8798a207b65ed3baba2228997a6","v":28},"uid":"TODO..."}

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
		args args
		want string
	}{
		{
			name: "ok",
			args: args{
				version:        1,
				schema:         "0x32275eb98dcb8f82848adef9fa52311cc9e83bc6fdb34c5f46ac4b8d957ad3d9",
				recipient:      "0x0000000000000000000000000000000000000000",
				time:           1703962538,
				expirationTime: 1703962537,
				revocable:      true,
				refUID:         "0x0000000000000000000000000000000000000000000000000000000000000000",
				data:           "0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000036f732b0000000000000000000000000000000000000000000000000000000000",
			},
			want: "0x27600687657c97bcdd6d137c62e727c805ac563b94fdc08b1ffe9d15cbd6f55d",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getOffChainUID(tt.args.version, tt.args.schema, tt.args.recipient, tt.args.time, tt.args.expirationTime, tt.args.revocable, tt.args.refUID, tt.args.data); got != tt.want {
				t.Errorf("getOffChainUID() = %v, want = %v", got, tt.want)
			}
		})
	}
}
