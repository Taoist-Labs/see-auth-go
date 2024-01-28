package common

import "testing"

func TestGetLatestBlockNumber(t *testing.T) {
	got, err := GetLatestBlockNumber()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("got = %d", got)
}
