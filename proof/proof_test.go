package proof

import (
	"reflect"
	"testing"
	"time"
)

var (
	privateKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	attester   = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	recipient  = "0x0000000000000000000000000000000000000000"

	proofLifetime = 60 * time.Second

	schemaData = &SchemaData{
		Signature: "0x123214hsdkf",
		Wallet:    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
		Vendor:    "os+",
	}
)

func TestSign(t *testing.T) {
	type args struct {
		recipient     string
		proofLifetime time.Duration
		schemaData    *SchemaData
	}
	tests := []struct {
		name string
		args args
		//want    string
		wantErr bool
	}{
		{
			name: "ok",
			args: args{
				recipient:     recipient,
				proofLifetime: proofLifetime,
				schemaData:    schemaData,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Sign(tt.args.recipient, tt.args.proofLifetime, tt.args.schemaData, privateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			//if got != tt.want {
			//	t.Errorf("Sign() got = %v, want %v", got, tt.want)
			//}
			if err == nil {
				t.Logf("%+v", got)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	type args struct {
		attester      string
		recipient     string
		proofLifetime time.Duration
	}
	tests := []struct {
		name           string
		args           args
		wantOk         bool
		wantSchemaData *SchemaData
		wantErr        bool
	}{
		{
			name: "ok",
			args: args{
				attester:  attester,
				recipient: recipient,
			},
			wantOk:         true,
			wantSchemaData: schemaData,
			wantErr:        false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof, err := Sign(tt.args.recipient, tt.args.proofLifetime, schemaData, privateKey)
			if err != nil {
				t.Errorf("Sign() error = %v", err)
				return
			}

			gotOk, gotSchemaData, err := Verify(tt.args.attester, tt.args.recipient, proof)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotOk != tt.wantOk {
				t.Errorf("Verify() gotOk = %v, want = %v", gotOk, tt.wantOk)
			}
			if !reflect.DeepEqual(gotSchemaData, tt.wantSchemaData) {
				t.Errorf("Verify() gotSchemaData = %v, want = %v", gotSchemaData, tt.wantSchemaData)
			}
		})
	}
}
