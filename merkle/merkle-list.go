package merkle

import (
	"math/big"

	"github.com/node101-io/mina-signer-go/poseidon"
)

type MerkleList struct {
	state  [][]byte
	root   []byte
	hasher *poseidon.Poseidon
}

func NewMerkleList() (*MerkleList, error) {

	input := big.NewInt(0).Bytes()

	poseidon := poseidon.NewPoseidon()
	hash, err := poseidon.Hash(input)
	if err != nil {
		return nil, err
	}

	var state [][]byte
	state = append(state, hash)

	return &MerkleList{
		state:  state,
		root:   hash,
		hasher: poseidon,
	}, nil
}

func (m *MerkleList) Append(element []byte) {
	if m == nil || m.hasher == nil {
		return
	}

	elementHash, err := m.hasher.Hash(element)
	if err != nil {
		return
	}

	input := make([]byte, 0, len(m.root)+len(elementHash))
	input = append(input, m.root...)
	input = append(input, elementHash...)

	nextRoot, err := m.hasher.Hash(input)
	if err != nil {
		return
	}

	m.root = nextRoot
	m.state = append(m.state, nextRoot)
}

func (m *MerkleList) Root() []byte {
	return m.root
}
