package signature_test

import (
	"encoding/hex"
	"testing"

	signaturesdk "github.com/node101-io/mina-signer-go/signature"
	"github.com/stretchr/testify/require"
)

func TestDecodeSignatureGetAndString(t *testing.T) {
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = byte(i)
	}

	sig, err := signaturesdk.NewSignatureFromBytes(raw)
	require.NotNil(t, sig)
	require.NoError(t, err)

	require.Equal(t, raw, sig.Bytes())
	require.Equal(t, hex.EncodeToString(raw), sig.String())
}
