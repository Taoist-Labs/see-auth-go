package seeauth

import (
	"errors"
	"strconv"

	"github.com/Taoist-Labs/see-auth-go/common"
	"github.com/Taoist-Labs/see-auth-go/proof"
	"github.com/Taoist-Labs/see-auth-go/signature"
	"github.com/patrickmn/go-cache"
)

// in-memory cache for proof-used-flag
// `defaultExpiration` is proofLifetime, but `cleanUpInterval` is proofLifetime*6 for performance,
// because even proof-used-flag is expired, it is not necessary to delete it immediately. we prefer performance nor memory-use
var defaultCache = cache.New(proofLifetime, proofLifetime*6)

// SeeDAOAuth authenticates a SeeAuth service
// `recipient` parameter is
// `seeAuth` parameter is the SeeAuth object, you can parse from the request body commonly.
// It returns the wallet address if the authentication is successful,otherwise it returns an error
func SeeDAOAuth(recipient string, seeAuth *SeeAuth) (string, error) {
	// ---> get proof-used-flag from cache
	key := seeAuth.Signature.Nonce // use `signature.nonce` as KEY
	if _, found := defaultCache.Get(key); found {
		return "", errors.New("Reuse proof")
	}

	// verify latest-block-number
	number, _ := strconv.Atoi(seeAuth.Signature.Nonce[16:])
	numberOnChain, _ := common.GetLatestBlockNumber()
	if number != 0 && numberOnChain != 0 && int(numberOnChain)-number > 5 {
		return "", errors.New("block number too old")
	}

	// proofing proof
	ok, schemaData, err := proof.Verify(attester, recipient, seeAuth.Proof.Proof)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", errors.New("Invalid proof")
	}

	// ---> set proof-used-flag from cache
	defaultCache.Set(key, struct{}{}, proofLifetime)

	// verify signature
	err = signature.Verify(seeAuth.Wallet, seeAuth.Signature.Domain, seeAuth.Signature.Nonce, seeAuth.Signature.Message, seeAuth.Signature.Signature)
	if err != nil {
		return "", errors.New("Invalid signature")
	}

	if schemaData.Wallet != seeAuth.Wallet {
		return "", errors.New("Invalid payload")
	}

	return seeAuth.Wallet, nil
}
