package minasignergo

import (
	"github.com/bronlabs/bron-crypto/pkg/hashing/poseidon"
)

const bronRate int = 64

type Poseidon struct {
	hasher *poseidon.Poseidon
}

func NewPoseidon() *Poseidon {
	return &Poseidon{
		hasher: poseidon.NewKimchi(),
	}
}

func (p *Poseidon) Hash(data []byte) ([]byte, error) {

	if len(data)%bronRate == 0 {
		return data, nil
	}

	multiplierRate := (len(data) / bronRate)

	expectedSize := (multiplierRate + 1) * bronRate

	padded := make([]byte, expectedSize)
	padded = append(padded, data...)

	for i := len(data); i < expectedSize; i++ {
		padded = append(padded, 0)
	}

	_, err := p.hasher.Write(padded)
	if err != nil {
		return nil, err
	}

	return p.hasher.Sum(nil), nil
}
