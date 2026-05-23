package merklelist

import (
	"bytes"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/node101-io/mina-signer-go/errors"
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

	if m == nil {
		return errors.ErrNilMerkleList
	}

	if m.hasher == nil {
		return errors.ErrNilHasher
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

	m.root = nextRoot
	m.state = append(m.state, m.root)

	return nil
}

func (m *MerkleList) Root() []byte {

	if m == nil {
		return nil
	}

	return bytes.Clone(m.root)
}

func (m *MerkleList) Zero() []byte {

	if m == nil {
		return nil
	}

	return pasta.NewPallasBaseField().Zero().Bytes()
}
