package proof

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Taoist-Labs/see-auth-go/proof/offchain"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

const (
	// --- polygon mumbai ---
	chainId            = 80001
	easContractAddress = "0xaEF4103A04090071165F78D45D83A0C0782c2B2a"
	easVersion         = "1.2.0"
	schemaUID          = "0x32275eb98dcb8f82848adef9fa52311cc9e83bc6fdb34c5f46ac4b8d957ad3d9"
)

// ------ ------ ------ ------ ------ ------ ------ ------ ------

var (
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
			{Name: "nonce", Type: "string"}, // TODO: should be uint256
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
		Version:           easVersion,
		ChainId:           math.NewHexOrDecimal256(chainId),
		VerifyingContract: easContractAddress,
	}
)

//type OffChainAttestationParams struct {
//	version string
//	schema string
//	recipient string
//	time uint64
//	expirationTime uint64
//	revocable bool
//	refUID string
//	data string
//}

type Proof struct {
	Sig    *offchain.Sig `json:"sig"`
	Signer string        `json:"signer"`
}

func Sign(recipient string, proofLifetime time.Duration, schemaData *SchemaData, privateKey string) (string, error) {
	key, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		return "", err
	}

	encodeData, err := offchain.SchemaEncode(schemaAbiTypes, []any{schemaData.Signature, common.HexToAddress(schemaData.Wallet), schemaData.Vendor})
	if err != nil {
		return "", err
	}
	typedDataMessage := apitypes.TypedDataMessage{
		"recipient":      recipient,
		"time":           fmt.Sprintf("%d", time.Now().UTC().Unix()),                    // Unix timestamp of current time
		"expirationTime": fmt.Sprintf("%d", time.Now().UTC().Add(proofLifetime).Unix()), // Unix timestamp of when attestation expires. (0 for no expiration)
		"revocable":      true,                                                          // Be aware that if your schema is not revocable, this MUST be false
		"version":        "1",                                                           // TODO: should be uint16, when is string https://polygon-mumbai.easscan.org/tools will not verify success
		"nonce":          "0",
		"schema":         schemaUID,
		"refUID":         "0x0000000000000000000000000000000000000000000000000000000000000000",
		"data":           encodeData,
	}

	typedData := &apitypes.TypedData{
		Types:       types,
		PrimaryType: primaryType,
		Domain:      typedDataDomain,
		Message:     typedDataMessage,
	}

	sig, err := offchain.SignOffChainAttestation(key, typedData)
	if err != nil {
		return "", err
	}

	publicKey := key.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	// fmt.Println(address)

	p, err := json.Marshal(&Proof{
		Sig:    sig,
		Signer: address,
	})
	if err != nil {
		return "", err
	}

	return string(p), nil
}

func Verify(attester, recipient, proof string) (bool, *SchemaData, error) {
	var p Proof
	err := json.Unmarshal([]byte(proof), &p)
	if err != nil {
		return false, nil, err
	}

	expectTypedData := &apitypes.TypedData{
		Types:       types,
		PrimaryType: primaryType,
		Domain:      typedDataDomain,
		Message:     nil, // this field not verify, so it can be nil
	}

	isValid, err := offchain.VerifyOffChainAttestation(attester, recipient, expectTypedData, p.Sig)
	if err != nil {
		return false, nil, err
	}
	if isValid {
		encodeData, err := offchain.SchemaDecode(schemaAbiTypes, fmt.Sprintf("%s", p.Sig.Message["data"]))
		if err != nil {
			return false, nil, err
		}
		return true, &SchemaData{
			Signature: fmt.Sprintf("%s", encodeData[0]),
			Wallet:    fmt.Sprintf("%s", encodeData[1]),
			Vendor:    fmt.Sprintf("%s", encodeData[2]),
		}, nil
	} else {
		return false, nil, nil
	}
}

// ------ ------ ------ ------ ------ ------ ------ ------ ------

var schemaAbiTypes = []string{"string", "address", "string"}

type SchemaData struct {
	Signature string `json:"signature"`
	Wallet    string `json:"wallet"`
	Vendor    string `json:"vendor"`
}
