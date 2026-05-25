package poseidon

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/hashing/poseidon"
	"github.com/node101-io/mina-signer-go/errors"
)

type Poseidon struct {
	hasher *poseidon.Poseidon
}

func NewPoseidon() *Poseidon {
	return &Poseidon{
		hasher: poseidon.NewKimchi(),
	}
}

func (p *Poseidon) getHasher() (*poseidon.Poseidon, error) {

	if p == nil {
		return nil, errors.ErrNilPoseidon
	}

	if p.hasher == nil {
		return nil, errors.ErrNilHasher
	}

	return p.hasher, nil
}

func (p *Poseidon) Hash(data []byte) ([]byte, error) {
	hasher, err := p.getHasher()
	if err != nil {
		return nil, err
	}
	hasher.Reset()
	defer hasher.Reset()

	field := pasta.NewPallasBaseField()
	rate := hasher.Rate()

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

	_, err = hasher.Write(encoded)
	if err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func (p *Poseidon) HashWithPrefix(prefix string, data []byte) ([]byte, error) {
	dataFields, err := o1jsBytesToFields(data)
	if err != nil {
		return nil, err
	}

	hash, err := p.HashFieldsWithPrefix(prefix, dataFields...)
	if err != nil {
		return nil, err
	}

	return hash, nil
}

func (p *Poseidon) HashFieldsWithPrefix(
	prefix string,
	fieldsToHash ...*pasta.PallasBaseFieldElement,
) ([]byte, error) {
	hasher, err := p.getHasher()
	if err != nil {
		return nil, err
	}
	hasher.Reset()
	defer hasher.Reset()

	field := pasta.NewPallasBaseField()
	rate := hasher.Rate()

	prefixField, err := prefixToField(prefix)
	if err != nil {
		return nil, err
	}

	prefixBlock := []*pasta.PallasBaseFieldElement{prefixField}
	for len(prefixBlock)%rate != 0 {
		prefixBlock = append(prefixBlock, field.Zero())
	}
	if err := hasher.Update(prefixBlock...); err != nil {
		return nil, err
	}

	if err := hasher.Update(padToRate(fieldsToHash, rate)...); err != nil {
		return nil, err
	}

	return hasher.Digest().Bytes(), nil
}
