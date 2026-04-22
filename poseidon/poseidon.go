package poseidon

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/hashing/poseidon"
	bronposeidon "github.com/bronlabs/bron-crypto/pkg/hashing/poseidon"
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

	field := pasta.NewPallasBaseField()
	rate := bronposeidon.NewKimchi().Rate()

	elements := make([]*pasta.PallasBaseFieldElement, 0, len(data))
	for _, char := range data {
		element, err := field.FromBytesBEReduce([]byte{char})
		if err != nil {
			return nil, err
		}
		elements = append(elements, element)
	}

	for len(elements)%rate != 0 {
		elements = append(elements, field.Zero())
	}

	encoded := make([]byte, 0, len(elements)*field.ElementSize())
	for _, element := range elements {
		encoded = append(encoded, element.Bytes()...)
	}

	_, err := p.hasher.Write(encoded)
	if err != nil {
		return nil, err
	}
	hash := p.hasher.Sum(nil)

	p.hasher.Reset()

	return hash, nil
}
