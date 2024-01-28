package common

import (
	"strconv"

	"github.com/ethereum/go-ethereum/rpc"
)

type block struct {
	Number string
}

// GetLatestBlockNumber
// mint one block every 12 seconds
func GetLatestBlockNumber() (blockNumber int64, err error) {
	client, err := rpc.Dial("https://rpc.ankr.com/eth")
	if err != nil {
		return
	}
	defer client.Close()
	var lastBlock block
	err = client.Call(&lastBlock, "eth_getBlockByNumber", "latest", true)
	if err != nil {
		return
	}

	return strconv.ParseInt(lastBlock.Number, 0, 0)
}
