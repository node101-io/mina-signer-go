package merkle

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/node101-io/mina-signer-go/poseidon"
)

type MerkleList struct {
	state  [][]byte
	root   []byte
	prefix string
	hasher *poseidon.Poseidon
}

func NewMerkleList(prefix string) (*MerkleList, error) {

	zero := pasta.NewPallasBaseField().Zero()

	poseidon := poseidon.NewPoseidon()

	return &MerkleList{
		state:  [][]byte{},
		root:   zero.Bytes(),
		prefix: prefix,
		hasher: poseidon,
	}, nil
}

func (m *MerkleList) Append(element []byte) error {
	if m == nil || m.hasher == nil {
		return nil
	}

	field := pasta.NewPallasBaseField()

	rootField, err := field.FromBytes(m.root)
	if err != nil {
		return err
	}

	valueField, err := field.FromBytes(element)
	if err != nil {
		return err
	}

	nextRoot, err := m.hasher.HashFieldsWithPrefix(m.prefix, rootField, valueField)
	if err != nil {
		return err
	}

	m.root = nextRoot.Bytes()
	m.state = append(m.state, m.root)

	return nil
}

func (m *MerkleList) Root() []byte {
	return m.root
}
