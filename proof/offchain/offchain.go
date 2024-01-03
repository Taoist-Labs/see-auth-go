package offchain

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

type (
	Sig struct {
		*apitypes.TypedData
		Signature *signature `json:"signature"`
		UID       string     `json:"uid"`
	}
	signature struct {
		R string `json:"r"`
		S string `json:"s"`
		V uint8  `json:"v"`
	}
)

func SignOffChainAttestation(privateKey *ecdsa.PrivateKey, typedData *apitypes.TypedData) (*Sig, error) {
	hash, err := signHash(typedData)
	if err != nil {
		return nil, err
	}

	sig, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return nil, fmt.Errorf("generate signatrue error: %s", err)
	}
	//fmt.Printf("signature: %s\n", hexutil.Encode(sig))
	r := hexutil.EncodeBig(new(big.Int).SetBytes(sig[:32]))
	s := hexutil.EncodeBig(new(big.Int).SetBytes(sig[32:64]))
	v := uint8(sig[64]) + 27

	offChainUID := getOffChainUID(typedData.Message)

	return &Sig{
		TypedData: typedData,
		Signature: &signature{
			R: r,
			S: s,
			V: v,
		},
		UID: offChainUID,
	}, nil
}

func VerifyOffChainAttestation(attester, recipient string, expectTypedData *apitypes.TypedData, sig *Sig) (bool, error) {
	// verify OffChainUID
	offChainUID := getOffChainUID(sig.Message)
	if offChainUID != sig.UID {
		return false, errors.New("Proof Error: proof uid not match")
	}

	// verify expiration time
	expirationTime, err := strconv.ParseInt(fmt.Sprintf("%s", sig.Message["expirationTime"]), 10, 64)
	if err != nil || time.Now().UTC().Unix() > expirationTime {
		return false, errors.New("Proof Error: proof expired")
	}

	// verify recipient
	if recipient != sig.Message["recipient"] {
		return false, errors.New("Proof Error: proof recipient not match")
	}

	if !reflect.DeepEqual(sig.Domain, expectTypedData.Domain) {
		return false, errors.New("Proof Error: domain not match")
	}
	if sig.PrimaryType != expectTypedData.PrimaryType {
		return false, errors.New("Proof Error: primary type not match")
	}
	// TODO Node has no `EIP712Domain` but Go has, so we can't compare `types`
	//if !reflect.DeepEqual(sig.Types, expectTypedData.Types) {
	//	return false, errors.New("Proof Error: types not match")
	//}
	if attester == "0x0000000000000000000000000000000000000000" {
		return false, errors.New("Proof Error: attester is zero address")
	}

	// verify signature
	bytes := make([]byte, 65)
	// s
	bigS, err := hexutil.DecodeBig(sig.Signature.S)
	if err != nil {
		return false, fmt.Errorf("Proof Error: decode signature 's' part error: %s", err)
	}
	copy(bytes[:32], bigS.Bytes()) // 0~31
	// r
	bigR, err := hexutil.DecodeBig(sig.Signature.R)
	if err != nil {
		return false, fmt.Errorf("Proof Error: decode signature 'r' part error: %s", err)
	}
	copy(bytes[32:64], bigR.Bytes()) // 32~63
	// v
	bytes[64] = sig.Signature.V - 27
	// start verify
	// <---------------------------
	// `EIP712Domain` is empty when proof generate by Node SDK
	if sig.TypedData.Types["EIP712Domain"] == nil {
		sig.TypedData.Types["EIP712Domain"] = []apitypes.Type{
			{Name: "name", Type: "string"},
			{Name: "version", Type: "string"},
			{Name: "chainId", Type: "uint256"},
			{Name: "verifyingContract", Type: "address"},
		}
	}
	// `Attest` 's `nonce` is empty when proof generate by Node SDK
	hasNonce := false
	for _, t := range sig.TypedData.Types["Attest"] {
		if t.Name == "nonce" {
			hasNonce = true
			break
		}
	}
	if !hasNonce {
		sig.TypedData.Types["Attest"] = append(sig.TypedData.Types["Attest"], apitypes.Type{Name: "nonce", Type: "string"})
	}
	// --------------------------->
	hash, err := signHash(sig.TypedData)
	if err != nil {
		return false, err
	}

	//fmt.Printf("crypto.SigToPub('%s', '%s')\n", hexutil.Encode(hash), hexutil.Encode(bytes))

	// method 1
	pubKey, err := crypto.SigToPub(hash, bytes)
	if err != nil {
		return false, fmt.Errorf("verify signatrue error: %s", err)
	}
	return crypto.PubkeyToAddress(*pubKey).Hex() != attester, nil

	// method 2
	//privateKey, err := crypto.HexToECDSA("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
	//publicKey := privateKey.Public()
	//publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	//publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	//return crypto.VerifySignature(publicKeyBytes, hash, bytes[:len(bytes)-1]), nil

	// method 3
	//pubKey, err := crypto.Ecrecover(hash, bytes)
	//if err != nil {
	//	return false, fmt.Errorf("verify signatrue error: %s", err)
	//}
	//return common.Bytes2Hex(pubKey) != attester, nil
}

func signHash(typedData *apitypes.TypedData) ([]byte, error) {
	// EIP-712 typed data marshalling
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return nil, fmt.Errorf("eip712domain hash struct error: %s", err)
	}
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return nil, fmt.Errorf("primaryType hash struct error: %s", err)
	}

	// add magic string prefix
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	return crypto.Keccak256(rawData), nil
}

func getOffChainUID(typedDataMessage apitypes.TypedDataMessage) string {
	// uint16 `solidityPackedKeccak256(["uint16"], [1])` ==> `0x49d03a195e239b52779866b33024210fc7dc66e9c2998975c0aa45c1702549d5`
	//i := uint16(1)
	//b := make([]byte, 2)
	//binary.BigEndian.PutUint16(b, i)
	//hash := crypto.Keccak256Hash(b) // ok!

	// uint32 `solidityPackedKeccak256(["uint32"], [0])` ==> `0xe8e77626586f73b955364c7b4bbf0bb7f7685ebd40e852b164633a4acbd3244c`
	//i := uint32(0)
	//b := make([]byte, 4)
	//binary.BigEndian.PutUint32(b, i)
	//hash := crypto.Keccak256Hash(b)

	// uint64 `solidityPackedKeccak256(["uint64"], [ethers.getBigInt(1704170581)])` ==> `0xb1be985224350e771be37af4d0f7b88b70838b66cf1d8e9b235c340f02662018`
	//i := uint64(1704170581)
	//b := make([]byte, 8)
	//binary.BigEndian.PutUint64(b, i)
	//hash := crypto.Keccak256Hash(b) //

	// bool `solidityPackedKeccak256(["bool"], [true])` ==> `0x5fe7f977e71dba2ea1a68e21057beebb9be2ac30c6410aa38d4f3fbe41dcffd2`
	//hash := crypto.Keccak256Hash([]byte{byte(1)}) // ok!

	// address `solidityPackedKeccak256(["address"], [ZeroAddress])` ==> `0x5380c7b7ae81a58eb98d9c78de4a1fd7fd9535fc953ed2be602daaa41767312a`
	//hash := crypto.Keccak256Hash(common.HexToAddress("0x0000000000000000000000000000000000000000").Bytes()) // ok!

	// bytes `solidityPackedKeccak256(["bytes"], [hexlify(toUtf8Bytes("0x32275eb98dcb8f82848adef9fa52311cc9e83bc6fdb34c5f46ac4b8d957ad3d9"))])` ==> `0x9757e21295030c208991811eeec75c3b72a5d240b528437c9082a2c5a81fe988`
	//hash := crypto.Keccak256Hash([]byte("0x32275eb98dcb8f82848adef9fa52311cc9e83bc6fdb34c5f46ac4b8d957ad3d9")) //

	// bytes `solidityPackedKeccak256(["bytes"], ["0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000036f732b0000000000000000000000000000000000000000000000000000000000"])` ==> `0x7f920a26f29e2a8912425dbbea4413524773668dd471bbfeac63a7ace970e721`
	//slice, _ := hexutil.Decode("0x000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb92266000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000036f732b0000000000000000000000000000000000000000000000000000000000")
	//hash := crypto.Keccak256Hash(slice) // ok!

	// bytes32 `solidityPackedKeccak256(["bytes32"], ["0x0000000000000000000000000000000000000000000000000000000000000000"])` ==> `0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563`
	//slice, _ := hexutil.Decode("0x0000000000000000000000000000000000000000000000000000000000000000")
	//hash := crypto.Keccak256Hash(slice) // ok!

	v, _ := strconv.ParseUint(fmt.Sprintf("%s", typedDataMessage["version"]), 10, 16)
	tim, _ := strconv.ParseUint(fmt.Sprintf("%s", typedDataMessage["time"]), 10, 64)
	expirationTime, _ := strconv.ParseUint(fmt.Sprintf("%s", typedDataMessage["expirationTime"]), 10, 64)
	var (
		version   uint16 = uint16(v)
		schema    string = fmt.Sprintf("%s", typedDataMessage["schema"])
		recipient string = fmt.Sprintf("%s", typedDataMessage["recipient"])
		revocable bool   = typedDataMessage["revocable"].(bool)
		refUID    string = fmt.Sprintf("%s", typedDataMessage["refUID"])
		data      string = fmt.Sprintf("%s", typedDataMessage["data"])
	)

	// `["uint16", "bytes", "address", "address", "uint64", "uint64", "bool", "bytes32", "bytes", "uint32"]`
	hash := crypto.Keccak256Hash(
		uin16Bytes(version),
		bytesBytes(schema),
		addressBytes(recipient),
		addressBytes("0x0000000000000000000000000000000000000000"),
		uint64Bytes(tim),
		uint64Bytes(expirationTime),
		boolBytes(revocable),
		bytes32Bytes(refUID),
		bytes32Bytes(data), // NOTICE HERE, not `bytesBytes(data)`
		uint32Bytes(0),
	)

	return hash.Hex()
}

func uin16Bytes(i uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return b
}

func uint32Bytes(i uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i)
	return b
}

func uint64Bytes(i uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, i)
	return b
}

func boolBytes(i bool) []byte {
	if i {
		return []byte{byte(1)}
	} else {
		return []byte{byte(0)}
	}
}

func addressBytes(address string) []byte {
	return common.HexToAddress(address).Bytes()
}

func bytesBytes(bytes string) []byte {
	return []byte(bytes)
}

func bytes32Bytes(bytes32 string) []byte {
	b, _ := hexutil.Decode(bytes32)
	return b
}
