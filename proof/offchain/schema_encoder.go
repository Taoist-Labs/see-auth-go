package offchain

import (
	"errors"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// SchemaEncode encodes the given types and arguments into a schema.
// `types` is solidity types, e.g. "uint256,string,address"
// `args` is the arguments to encode, e.g. uint256(1),"hello",common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
// for example:
//
// SchemaEncode([]string"address", "string"}, common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), "os+")
// SchemaEncode([]string"address", "bytes"}, common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), []byte("os+"))
//
// for more examples, see `schema_encoder_test.go`
func SchemaEncode(types []string, args []any) (string, error) {
	if len(types) != len(args) {
		return "", errors.New("length of types and arguments do not match")
	}

	//arguments := make(abi.Arguments, len(types))
	//for i, t := range types {
	//	typ, err := abi.NewType(t, "", nil)
	//	if err != nil {
	//		return "", err
	//	}
	//	arguments[i] = abi.Argument{
	//		Type: typ,
	//	}
	//}
	arguments, err := parseSchema(types)
	if err != nil {
		return "", err
	}

	bytes, err := arguments.Pack(args...)
	if err != nil {
		return "", err
	}
	return hexutil.Encode(bytes), nil
}

// SchemaDecode decodes the given types and arguments into a schema.
// `types` is solidity types, e.g. "uint256,string,address"
// `args` is the arguments to encode, e.g. uint256(1),"hello",common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
// for example:
//
// SchemaDecode([]string"address", "string"}, "0x000000000000000000...0x0000000000000000000")
// SchemaDecode([]string"address", "bytes"}, "0x0000000000000000000...0x0000000000000000000")
//
// for more examples, see `schema_encoder_test.go`
func SchemaDecode(types []string, data string) ([]any, error) {
	bytes, err := hexutil.Decode(data)
	if err != nil {
		return nil, err
	}

	arguments, err := parseSchema(types)
	if err != nil {
		return nil, err
	}

	return arguments.Unpack(bytes)
}

func parseSchema(types []string) (abi.Arguments, error) {
	arguments := make(abi.Arguments, len(types))
	for i, t := range types {
		typ, err := abi.NewType(t, "", nil)
		if err != nil {
			return nil, err
		}
		arguments[i] = abi.Argument{
			Type: typ,
		}
	}

	return arguments, nil
}
