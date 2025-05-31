package signature_test

import (
	"encoding/json"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"testing"

	"github.com/node101-io/mina-signer-go/keys"
	"github.com/node101-io/mina-signer-go/poseidonbigint"
	"github.com/node101-io/mina-signer-go/signature"
)

type TestCase struct {
	PrivateKey struct {
		S string `json:"s"`
	} `json:"privateKey"`
	Message   []string `json:"message"`
	Signature struct {
		R string `json:"r"`
		S string `json:"s"`
	} `json:"signature"`
}

var maxTests = 10000

func TestSignaturesFromJSON(t *testing.T) {
	data, err := os.ReadFile("testJSON/1.json")
	if err != nil {
		t.Fatalf("Failed to read test JSON: %v", err)
	}

	var testCases []TestCase
	if err := json.Unmarshal(data, &testCases); err != nil {
		t.Fatalf("Failed to parse test JSON: %v", err)
	}

	if len(testCases) > maxTests {
		testCases = testCases[:maxTests]
	}

	network := "testnet"

	failed := 0
	for i, tc := range testCases {
		if i%(maxTests/20) == 0 {
			fmt.Printf("Processed %d/%d (%.2f%%) | Failed: %d\n",
				i, len(testCases), 100*float64(i)/float64(len(testCases)), failed)
		}
		priv, ok := new(big.Int).SetString(tc.PrivateKey.S, 10)
		if !ok {
			t.Errorf("Case %d: invalid private key: %v", i, tc.PrivateKey.S)
			failed++
			continue
		}
		msg := make([]*big.Int, len(tc.Message))
		for j, m_str := range tc.Message {
			bi, ok_m := new(big.Int).SetString(m_str, 10)
			if !ok_m {
				t.Errorf("Case %d: invalid message[%d]: %v", i, j, m_str)
				failed++
				continue
			}
			msg[j] = bi
		}
		r, okR := new(big.Int).SetString(tc.Signature.R, 10)
		s, okS := new(big.Int).SetString(tc.Signature.S, 10)
		if !okR || !okS {
			t.Errorf("Case %d: invalid signature (R/S): %v, %v", i, tc.Signature.R, tc.Signature.S)
			failed++
			continue
		}

		expectedSignature := &signature.Signature{R: r, S: s}

		privateKey := keys.PrivateKey{Value: priv}
		pubKey := privateKey.ToPublicKey()

		msgInput := poseidonbigint.HashInput{
			Fields: msg,
		}

		derivedSignature, err := privateKey.Sign(msgInput, network)

		if err != nil {
			t.Errorf("Case %d: Signing failed with error: %v\nPriv: %s\nMsg: %v", i, err, priv, tc.Message)
			failed++
			continue
		}

		if derivedSignature.R.Cmp(expectedSignature.R) != 0 || derivedSignature.S.Cmp(expectedSignature.S) != 0 {
			t.Errorf("Case %d: Signature mismatch\nExpected: (R: %s, S: %s)\nGot: (R: %s, S: %s)\nPriv: %s\nMsg: %v",
				i, expectedSignature.R, expectedSignature.S, derivedSignature.R, derivedSignature.S, priv, tc.Message)
			failed++
			continue
		}

		if !pubKey.Verify(expectedSignature, msgInput, network) {
			t.Errorf("Case %d: Signature verification failed\nPriv: %s\nMsg: %v\nSignature: (R: %s, S: %s)", i, priv, tc.Message, expectedSignature.R, expectedSignature.S)
			failed++
		}
	}
	if failed > 0 {
		t.Logf("Total failed cases in TestSignaturesFromJSON: %d/%d", failed, len(testCases))
	}
}

func TestInvalidSignature(t *testing.T) {
	data, err := os.ReadFile("testJSON/1.json")
	if err != nil {
		t.Fatalf("Failed to read test JSON: %v", err)
	}

	var testCases []TestCase
	if err := json.Unmarshal(data, &testCases); err != nil {
		t.Fatalf("Failed to parse test JSON: %v", err)
	}

	if len(testCases) > maxTests {
		testCases = testCases[:maxTests]
	}

	network := "testnet"

	failed := 0
	for i, tc := range testCases {
		if i%(maxTests/20) == 0 {
			fmt.Printf("Processed %d/%d (%.2f%%) | Failed: %d\n",
				i, len(testCases), 100*float64(i)/float64(len(testCases)), failed)
		}
		priv, ok := new(big.Int).SetString(tc.PrivateKey.S, 10)
		if !ok {
			t.Errorf("Case %d: invalid private key: %v", i, tc.PrivateKey.S)
			failed++
			continue
		}
		msg := make([]*big.Int, len(tc.Message))
		for j, m_str := range tc.Message {
			bi, ok_m := new(big.Int).SetString(m_str, 10)
			if !ok_m {
				t.Errorf("Case %d: invalid message[%d]: %v", i, j, m_str)
				failed++
				continue
			}
			msg[j] = bi
		}
		r, okR := new(big.Int).SetString(tc.Signature.R, 10)
		s, okS := new(big.Int).SetString(tc.Signature.S, 10)
		if !okR || !okS {
			t.Errorf("Case %d: invalid signature (R/S): %v, %v", i, tc.Signature.R, tc.Signature.S)
			failed++
			continue
		}

		validSignature := &signature.Signature{R: r, S: s}

		privateKey := keys.PrivateKey{Value: priv}
		pubKey := privateKey.ToPublicKey()

		intruderVal := new(big.Int).Add(priv, big.NewInt(1))
		intruderPrivateKey := keys.PrivateKey{Value: intruderVal}
		intruderPubKey := intruderPrivateKey.ToPublicKey()

		corruptedMsg := make([]*big.Int, len(msg))
		copy(corruptedMsg, msg)
		if len(msg) > 0 && len(corruptedMsg) > 0 {
			idx := rand.Intn(len(msg))
			corruptedMsg[idx] = new(big.Int).Add(msg[idx], big.NewInt(1))
		}

		msgInput := poseidonbigint.HashInput{Fields: msg}
		corruptedMsgInput := poseidonbigint.HashInput{Fields: corruptedMsg}

		if pubKey.Verify(validSignature, corruptedMsgInput, network) {
			t.Errorf("Case %d: Signature verification should have failed with modified message\n", i)
			failed++
		}

		if intruderPubKey.Verify(validSignature, msgInput, network) {
			t.Errorf("Case %d: Signature verification should have failed with intruder's public key\n", i)
			failed++
		}
	}
	if failed > 0 {
		t.Logf("Total failed cases in TestInvalidSignature: %d/%d", failed, len(testCases))
	}
}
