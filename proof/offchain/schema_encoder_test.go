package offchain

import (
	"reflect"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestSchemaEncode(t *testing.T) {
	type args struct {
		types []string
		args  []any
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Ok1",
			args: args{
				types: []string{"address", "string"},
				args:  []any{common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), "os+"},
			},
			want:    "0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000036f732b0000000000000000000000000000000000000000000000000000000000",
			wantErr: false,
		},
		{
			name: "Ok2",
			args: args{
				types: []string{"uint8", "uint16", "uint32", "uint64", "bool", "bytes", "string", "address"},
				args:  []any{uint8(1), uint16(1), uint32(1), uint64(1), false, []byte("bytes"), "test", common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")},
			},
			want:    "0x0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb922660000000000000000000000000000000000000000000000000000000000000005627974657300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000047465737400000000000000000000000000000000000000000000000000000000",
			wantErr: false,
		},
		//{
		//	name: "Ok3", // TODO how to pass uint128?
		//	args: args{
		//		types: []string{"uint128", "uint256"},
		//		args:  []any{common.LeftPadBytes(big.NewInt(1).Bytes(), 32), common.LeftPadBytes(big.NewInt(1).Bytes(), 32)},
		//	},
		//	want:    "",
		//	wantErr: false,
		//},
		{
			name: "Error: length not match",
			args: args{
				types: []string{"uint8", "uint16", "string", "address"},
				args:  []any{uint8(1), uint16(1)},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Error: type not correct",
			args: args{
				types: []string{"uint1", "uint16"},
				args:  []any{uint8(1), uint16(1)},
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SchemaEncode(tt.args.types, tt.args.args)
			if (err != nil) != tt.wantErr {
				t.Errorf("SchemaEncode() error = %v, wantErr = %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SchemaEncode() got = %v, want = %v", got, tt.want)
			}
		})
	}
}

func TestSchemaDecode(t *testing.T) {
	type args struct {
		types []string
		args  []any
	}
	tests := []struct {
		name    string
		args    args
		want    []any
		wantErr bool
	}{
		{
			name: "Ok1",
			args: args{
				types: []string{"address", "string"},
				args:  []any{common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), "os+"},
			},
			want:    []any{common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), "os+"},
			wantErr: false,
		},
		{
			name: "Ok2",
			args: args{
				types: []string{"uint8", "uint16", "uint32", "uint64", "bool", "bytes", "string", "address"},
				args:  []any{uint8(1), uint16(1), uint32(1), uint64(1), false, []byte("bytes"), "test", common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")},
			},
			want:    []any{uint8(1), uint16(1), uint32(1), uint64(1), false, []byte("bytes"), "test", common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")},
			wantErr: false,
		},
		{
			name: "Error: length not match",
			args: args{
				types: []string{"uint8", "uint16", "string", "address"},
				args:  []any{uint8(1), uint16(1)},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Error: type not correct",
			args: args{
				types: []string{"uint1", "uint16"},
				args:  []any{uint8(1), uint16(1)},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := SchemaEncode(tt.args.types, tt.args.args)
			got, err := SchemaDecode(tt.args.types, data)
			if (err != nil) != tt.wantErr {
				t.Errorf("SchemaDecode() error = %v, wantErr = %v", err, tt.wantErr)
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("SchemaDecode() got = %v, want = %v", got, tt.want)
				return
			}
			for i, v := range got {
				if !reflect.DeepEqual(v, tt.want[i]) {
					t.Errorf("SchemaDecode() got[%d] = %v, want[%d] = %v", i, got[i], i, tt.want[i])
					return
				}
			}
		})
	}
}
