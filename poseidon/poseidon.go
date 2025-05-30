package poseidon

import (
	"errors"
	"github.com/node101-io/mina-signer-go/constants"
	"github.com/node101-io/mina-signer-go/field"
	"math/big"
)

func assertPositiveInteger(x int, name string) {
	if x <= 0 {
		panic(name + " must be a positive integer")
	}
}

func strMatrixToBigInt(m [][]string) [][]*big.Int {
	out := make([][]*big.Int, len(m))
	for i := range m {
		out[i] = make([]*big.Int, len(m[i]))
		for j := range m[i] {
			val := new(big.Int)
			val.SetString(m[i][j], 0)
			out[i][j] = val
		}
	}
	return out
}

func fieldToGroup(x *big.Int) (*ECPoint, error) {
	return nil, errors.New("fieldToGroup: not implemented")
}

type ECPoint struct {
	X *big.Int
	Y *big.Int
}

func makeHashToGroup(hash func([]*big.Int) *big.Int) func([]*big.Int) *ECPoint {
	return func(input []*big.Int) *ECPoint {
		digest := hash(input)
		g, err := fieldToGroup(digest)
		if err != nil || g == nil {
			return nil
		}
		if g.Y.Bit(0) == 1 {
			yNeg := field.Fp.Negate(g.Y)
			return &ECPoint{X: g.X, Y: yNeg}
		}
		return g
	}
}

type Poseidon struct {
	InitialState func() []*big.Int
	Update       func(state []*big.Int, input []*big.Int) []*big.Int
	Hash         func(input []*big.Int) *big.Int
	HashToGroup  func(input []*big.Int) *ECPoint
}

func dot(Fp field.FiniteField, v1, v2 []*big.Int) *big.Int {
	if len(v1) != len(v2) {
		panic("dot: mismatched lengths")
	}
	acc := new(big.Int)
	for i := range v1 {
		acc = Fp.Add(acc, Fp.Mul(v1[i], v2[i]))
	}
	return acc
}

func CreatePoseidon(Fp field.FiniteField, params constants.PoseidonParams) *Poseidon {
	fullRounds := params.FullRounds
	partialRounds := params.PartialRounds
	hasInitialRoundConstant := params.HasInitialRoundConstant
	stateSize := params.StateSize
	rate := params.Rate
	power := params.Power
	roundConstants := strMatrixToBigInt(params.RoundConstants)
	mds := strMatrixToBigInt(params.MDS)

	if partialRounds != 0 {
		panic("partialRounds not supported")
	}
	assertPositiveInteger(rate, "rate")
	assertPositiveInteger(fullRounds, "fullRounds")
	assertPositiveInteger(power, "power")

	powerBig := big.NewInt(int64(power))

	initialState := func() []*big.Int {
		state := make([]*big.Int, stateSize)
		for i := range state {
			state[i] = big.NewInt(0)
		}
		return state
	}

	permutation := func(state []*big.Int) {
		offset := 0
		if hasInitialRoundConstant {
			for i := 0; i < stateSize; i++ {
				state[i] = Fp.Add(state[i], roundConstants[0][i])
			}
			offset = 1
		}
		for round := 0; round < fullRounds; round++ {
			for i := 0; i < stateSize; i++ {
				state[i] = Fp.Power(state[i], powerBig)
			}
			oldState := make([]*big.Int, len(state))
			copy(oldState, state)
			for i := 0; i < stateSize; i++ {
				state[i] = dot(Fp, mds[i], oldState)
				state[i] = Fp.Add(state[i], roundConstants[round+offset][i])
			}
		}
	}

	update := func(state []*big.Int, input []*big.Int) []*big.Int {
		newState := make([]*big.Int, len(state))
		copy(newState, state)

		if len(input) == 0 {
			permutation(newState)
			return newState
		}
		n := ((len(input) + rate - 1) / rate) * rate
		paddedInput := make([]*big.Int, n)
		copy(paddedInput, input)
		for i := len(input); i < n; i++ {
			paddedInput[i] = big.NewInt(0)
		}
		for blockIdx := 0; blockIdx < n; blockIdx += rate {
			for i := 0; i < rate; i++ {
				newState[i] = Fp.Add(newState[i], paddedInput[blockIdx+i])
			}
			permutation(newState)
		}
		return newState
	}

	hash := func(input []*big.Int) *big.Int {
		state := update(initialState(), input)
		return state[0]
	}

	ps := &Poseidon{
		InitialState: initialState,
		Update:       update,
		Hash:         hash,
	}
	ps.HashToGroup = makeHashToGroup(hash)
	return ps
}
