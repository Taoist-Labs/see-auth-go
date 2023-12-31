package offchain

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

func TestSignOffchainAttestation(t *testing.T) {
	privateKey, err := crypto.HexToECDSA("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	if err != nil {
		t.Error(0, err)
	}

	j := `{
  "domain": {
    "name": "EAS Attestation",
    "version": "1.2.0",
    "chainId": "80001",
    "verifyingContract": "0xaEF4103A04090071165F78D45D83A0C0782c2B2a"
  },
  "primaryType": "Attest",
  "message": {
    "recipient": "0x0000000000000000000000000000000000000000",
    "time": 1703962538,
    "expirationTime": 1703962537,
    "revocable": true,
    "version": 1,
    "schema": "0x32275eb98dcb8f82848adef9fa52311cc9e83bc6fdb34c5f46ac4b8d957ad3d9",
    "refUID": "0x0000000000000000000000000000000000000000000000000000000000000000",
    "data": "0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000036f732b0000000000000000000000000000000000000000000000000000000000"
  },
  "types": {
	"EIP712Domain": [
          {
            "name": "name",
            "type": "string"
          },
          {
            "name": "version",
            "type": "string"
          },
          {
            "name": "chainId",
            "type": "uint256"
          },
          {
            "name": "verifyingContract",
            "type": "address"
          }
        ],
    "Attest": [
      {
        "name": "version",
        "type": "uint16"
      },
      {
        "name": "schema",
        "type": "bytes32"
      },
      {
        "name": "recipient",
        "type": "address"
      },
      {
        "name": "time",
        "type": "uint64"
      },
      {
        "name": "expirationTime",
        "type": "uint64"
      },
      {
        "name": "revocable",
        "type": "bool"
      },
      {
        "name": "refUID",
        "type": "bytes32"
      },
      {
        "name": "data",
        "type": "bytes"
      }
    ]
  }
}`

	var typedData apitypes.TypedData
	err = json.Unmarshal([]byte(j), &typedData)
	if err != nil {
		t.Error(1, err)
	}

	//// ----------------------------------------------------------------------------
	//// ----------------------------------------------------------------------------
	//
	//sighash := typedData.TypeHash(typedData.PrimaryType)
	//signature, err := crypto.Sign(sighash, privateKey)
	//if err != nil {
	//	t.Error(4, err)
	//}
	//
	//ss := hexutil.Encode(signature)
	//t.Logf("signature: %s", ss)
	//
	//r := new(big.Int).SetBytes(signature[:32])
	//s := new(big.Int).SetBytes(signature[32:64])
	//v := uint8(signature[64]) + 27
	//
	//t.Logf("r: %s", hexutil.EncodeBig(r))
	//t.Logf("s: %s", hexutil.EncodeBig(s))
	//t.Logf("v: %d", v)
	//
	//publicKeyBytes := common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266").Bytes()
	//
	////publicKey := privateKey.Public()
	////publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	////publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	//
	//signatureNoRecoverID := signature[:len(signature)-1] // remove recovery ID
	//verified := crypto.VerifySignature(publicKeyBytes, sighash, signatureNoRecoverID)
	//fmt.Println(verified)

	// ----------------------------------------------------------------------------
	// ----------------------------------------------------------------------------

	// EIP-712 typed data marshalling
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		t.Error(1, err)
	}
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		t.Error(2, err)
	}

	// add magic string prefix
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	sighash := crypto.Keccak256(rawData)
	t.Log("SIG HASH:", hexutil.Encode(sighash))
	signature, err := crypto.Sign(sighash, privateKey)
	if err != nil {
		t.Error(4, err)
	}
	ss := hexutil.Encode(signature)
	t.Logf("signature: %s", ss)

	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:64])
	v := uint8(signature[64]) + 27

	t.Logf("r: %s", hexutil.EncodeBig(r))
	t.Logf("s: %s", hexutil.EncodeBig(s))
	t.Logf("v: %d", v)

	// ----------------------------------------------------------------------------

	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	signatureNoRecoverID := signature[:len(signature)-1] // remove recovery ID
	verified := crypto.VerifySignature(publicKeyBytes, sighash, signatureNoRecoverID)
	fmt.Println(verified)

	// ----------------------------------------------------------------------------

	pubkey, err := crypto.SigToPub(sighash, signature)
	fmt.Println(crypto.PubkeyToAddress(*pubkey).Hex())
}

func TestSignOffchainAttestation2(t *testing.T) {
	//Uint256, _    := abi.NewType("uint256", "", nil)
	//Uint64, _ := abi.NewType("uint64", "", nil)
	//Uint32, _ := abi.NewType("uint32", "", nil)
	//Uint16, _ := abi.NewType("uint16", "", nil)
	String, _ := abi.NewType("string", "", nil)
	//Bool, _ := abi.NewType("bool", "", nil)
	//Bytes, _ := abi.NewType("bytes", "", nil)
	//Bytes32, _ := abi.NewType("bytes32", "", nil)
	Address, _ := abi.NewType("address", "", nil)
	//Uint64Arr, _  := abi.NewType("uint64[]", "", nil)
	//AddressArr, _ := abi.NewType("address[]", "", nil)
	//Int8, _       := abi.NewType("int8", "", nil)

	a := abi.Arguments{
		{
			Type: Address,
		},
		{
			Type: String,
		},
	}

	//bytes, err := a.Pack(uint16(1), []byte("0x32275eb98dcb8f82848adef9fa52311cc9e83bc6fdb34c5f46ac4b8d957ad3d9"),
	//	common.HexToAddress("0x0000000000000000000000000000000000000000"), common.HexToAddress("0x0000000000000000000000000000000000000000"),
	//	uint64(1703962538), uint64(1703962537), true,
	//	//[]byte("0x0000000000000000000000000000000000000000000000000000000000000000")[:32],
	//	[]byte("0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000036f732b0000000000000000000000000000000000000000000000000000000000"),
	//	uint32(0))
	bytes, err := a.Pack(common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), "os+")
	if err != nil {
		t.Error(err)
	}
	xx := hexutil.Encode(bytes)
	fmt.Println(xx)

	v, err := a.Unpack(bytes)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("%s %s\n", v[0], v[1])

	bbb, _ := hexutil.Decode(xx)
	v2, err := a.Unpack(bbb)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("%s %s\n", v2[0], v2[1])
}
