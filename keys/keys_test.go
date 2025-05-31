package keys_test

import (
	"math/big"
	"testing"

	"github.com/node101-io/mina-signer-go/keys"
)

func TestPrivateKey_MarshalUnmarshalBytes(t *testing.T) {
	tests := []struct {
		name     string
		original *big.Int
		wantErr  bool
	}{
		{
			name:     "valid private key",
			original: big.NewInt(1234567890123456789),
			wantErr:  false,
		},
		{
			name:     "zero private key",
			original: big.NewInt(0),
			wantErr:  false,
		},
		{
			name:     "large private key (still fits in 32 bytes)",
			original: new(big.Int).Lsh(big.NewInt(1), 250), // 2^250
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privKey := keys.PrivateKey{Value: tt.original}

			marshaledBytes, err := privKey.MarshalBytes()
			if (err != nil) != tt.wantErr {
				t.Errorf("PrivateKey.MarshalBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if len(marshaledBytes) != keys.PrivateKeyByteSize {
				t.Errorf("PrivateKey.MarshalBytes() output length = %d, want %d", len(marshaledBytes), keys.PrivateKeyByteSize)
			}

			var newPrivKey keys.PrivateKey
			err = newPrivKey.UnmarshalBytes(marshaledBytes)
			if err != nil {
				t.Errorf("PrivateKey.UnmarshalBytes() error = %v", err)
				return
			}

			if privKey.Value.Cmp(newPrivKey.Value) != 0 {
				t.Errorf("Unmarshaled PrivateKey.Value = %v, want %v", newPrivKey.Value, privKey.Value)
			}
		})
	}

	t.Run("unmarshal with incorrect data length", func(t *testing.T) {
		var pk keys.PrivateKey
		shortData := make([]byte, keys.PrivateKeyByteSize-1)
		if err := pk.UnmarshalBytes(shortData); err == nil {
			t.Error("PrivateKey.UnmarshalBytes() expected error for short data, got nil")
		}
		longData := make([]byte, keys.PrivateKeyByteSize+1)
		if err := pk.UnmarshalBytes(longData); err == nil {
			t.Error("PrivateKey.UnmarshalBytes() expected error for long data, got nil")
		}
	})

	t.Run("marshal nil private key", func(t *testing.T) {
		var nilPrivKey *keys.PrivateKey
		if _, err := nilPrivKey.MarshalBytes(); err == nil {
			t.Error("(*PrivateKey)(nil).MarshalBytes() expected error, got nil")
		}

		nilValuePrivKey := keys.PrivateKey{Value: nil}
		if _, err := nilValuePrivKey.MarshalBytes(); err == nil {
			t.Error("PrivateKey{Value:nil}.MarshalBytes() expected error, got nil")
		}
	})
}

func TestPublicKey_MarshalUnmarshalBytes(t *testing.T) {
	tests := []struct {
		name          string
		originalX     *big.Int
		originalIsOdd bool
		wantErr       bool
	}{
		{
			name:          "valid public key, isOdd true",
			originalX:     big.NewInt(987654321987654321),
			originalIsOdd: true,
			wantErr:       false,
		},
		{
			name:          "valid public key, isOdd false",
			originalX:     big.NewInt(123),
			originalIsOdd: false,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKey := keys.PublicKey{X: tt.originalX, IsOdd: tt.originalIsOdd}

			marshaledBytes, err := pubKey.MarshalBytes()
			if (err != nil) != tt.wantErr {
				t.Errorf("PublicKey.MarshalBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			if len(marshaledBytes) != keys.PublicKeyTotalByteSize {
				t.Errorf("PublicKey.MarshalBytes() output length = %d, want %d", len(marshaledBytes), keys.PublicKeyTotalByteSize)
			}

			var newPubKey keys.PublicKey
			err = newPubKey.UnmarshalBytes(marshaledBytes)
			if err != nil {
				t.Errorf("PublicKey.UnmarshalBytes() error = %v", err)
				return
			}

			if pubKey.X.Cmp(newPubKey.X) != 0 {
				t.Errorf("Unmarshaled PublicKey.X = %v, want %v", newPubKey.X, pubKey.X)
			}
			if pubKey.IsOdd != newPubKey.IsOdd {
				t.Errorf("Unmarshaled PublicKey.IsOdd = %v, want %v", newPubKey.IsOdd, pubKey.IsOdd)
			}
		})
	}

	t.Run("unmarshal with incorrect data length", func(t *testing.T) {
		var pk keys.PublicKey
		shortData := make([]byte, keys.PublicKeyTotalByteSize-1)
		if err := pk.UnmarshalBytes(shortData); err == nil {
			t.Error("PublicKey.UnmarshalBytes() expected error for short data, got nil")
		}
		longData := make([]byte, keys.PublicKeyTotalByteSize+1)
		if err := pk.UnmarshalBytes(longData); err == nil {
			t.Error("PublicKey.UnmarshalBytes() expected error for long data, got nil")
		}
	})

	t.Run("unmarshal with invalid IsOdd byte", func(t *testing.T) {
		var pk keys.PublicKey
		invalidIsOddData := make([]byte, keys.PublicKeyTotalByteSize)
		invalidIsOddData[keys.PublicKeyXByteSize] = 0x05 // Neither 0x00 nor 0x01
		if err := pk.UnmarshalBytes(invalidIsOddData); err == nil {
			t.Error("PublicKey.UnmarshalBytes() expected error for invalid IsOdd byte, got nil")
		}
	})

	t.Run("marshal nil public key", func(t *testing.T) {
		var nilPubKey *keys.PublicKey
		if _, err := nilPubKey.MarshalBytes(); err == nil {
			t.Error("(*PublicKey)(nil).MarshalBytes() expected error, got nil")
		}

		nilXPubKey := keys.PublicKey{X: nil, IsOdd: false}
		if _, err := nilXPubKey.MarshalBytes(); err == nil {
			t.Error("PublicKey{X:nil}.MarshalBytes() expected error, got nil")
		}
	})

}

// TestMarshalUnmarshalSymmetry tests that a private key can be marshaled and unmarshaled
// back to its public key, and the result is the same as deriving the public key directly.
func TestMarshalUnmarshalSymmetry(t *testing.T) {
	privVal := big.NewInt(1234567891011121314)
	originalPrivKey := keys.PrivateKey{Value: privVal}

	originalPubKey := originalPrivKey.ToPublicKey()

	marshaledPrivBytes, err := originalPrivKey.MarshalBytes()
	if err != nil {
		t.Fatalf("Failed to marshal original private key: %v", err)
	}

	var unmarshaledPrivKey keys.PrivateKey
	err = unmarshaledPrivKey.UnmarshalBytes(marshaledPrivBytes)
	if err != nil {
		t.Fatalf("Failed to unmarshal private key bytes: %v", err)
	}

	derivedPubKeyFromUnmarshaled := unmarshaledPrivKey.ToPublicKey()

	if !originalPubKey.Equal(derivedPubKeyFromUnmarshaled) {
		t.Errorf("PublicKey derived from unmarshaled private key does not match original.\nOriginal: X=%s, IsOdd=%t\nDerived:  X=%s, IsOdd=%t",
			originalPubKey.X.String(), originalPubKey.IsOdd,
			derivedPubKeyFromUnmarshaled.X.String(), derivedPubKeyFromUnmarshaled.IsOdd)
	}

	marshaledPubBytes, err := originalPubKey.MarshalBytes()
	if err != nil {
		t.Fatalf("Failed to marshal original public key: %v", err)
	}

	var unmarshaledPubKey keys.PublicKey
	err = unmarshaledPubKey.UnmarshalBytes(marshaledPubBytes)
	if err != nil {
		t.Fatalf("Failed to unmarshal public key bytes: %v", err)
	}

	if !originalPubKey.Equal(unmarshaledPubKey) {
		t.Errorf("Unmarshaled public key does not match original.\nOriginal:   X=%s, IsOdd=%t\nUnmarshaled: X=%s, IsOdd=%t",
			originalPubKey.X.String(), originalPubKey.IsOdd,
			unmarshaledPubKey.X.String(), unmarshaledPubKey.IsOdd)
	}
}
