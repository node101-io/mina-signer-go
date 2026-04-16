package poseidon_test

import (
	"crypto/rand"
	"strconv"
	"testing"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	minaposeidon "github.com/node101-io/mina-signer-go/poseidon"
	"github.com/stretchr/testify/require"
)

var preGeneratedHashes = []string{

	"26632705941655164654352723360400804424085451887804283762208317966481005588949",

	"6136449836718800657582521710128248415152293080649145466535622117327729394426",

	"19295812424113345714738203788211272415025519242241902701641195346503819725299",

	"2390842538610180928584876701605337612567568687146689545756451034471318367234",

	"19652177132111325084141502472991173790231553092979104179762890353199342658452",

	"10089277980346438794339869817305426448198901812641778408126625349544111999896",

	"7602399819520503390410796573504094649914961951106657143384076684990706503490",

	"2803856553330975317632632736682064799672802682865384649257318880955933421392",

	"8376513644701965132503787714080702151758202204442900750349808250757654059542",

	"19806809820021140177284890502660164956188967384589944995495276262929962145317",
}

func TestPoseidonHash(t *testing.T) {

	for i, pregenHash := range preGeneratedHashes {

		poseidon := minaposeidon.NewPoseidon()

		hash, err := poseidon.Hash([]byte("message" + strconv.Itoa(i)))

		require.NoError(t, err)
		require.NotNil(t, hash)

		hashField, err := pasta.NewPallasBaseField().FromBytes(hash)
		require.NoError(t, err)
		require.Equal(t, pregenHash, hashField.String())

	}

}

func TestHashDivisibleByBronRate(t *testing.T) {

	b := make([]byte, 64)

	_, err := rand.Read(b)
	require.NoError(t, err)

	poseidon := minaposeidon.NewPoseidon()

	hash, err := poseidon.Hash(b)
	require.NoError(t, err)
	require.NotNil(t, hash)

}
func TestHashNotDivisibleByBronRate(t *testing.T) {

	b := make([]byte, 65)

	_, err := rand.Read(b)
	require.NoError(t, err)

	poseidon := minaposeidon.NewPoseidon()

	hash, err := poseidon.Hash(b)
	require.NoError(t, err)
	require.NotNil(t, hash)

}
