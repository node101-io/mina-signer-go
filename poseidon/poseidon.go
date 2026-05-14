package poseidon

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/hashing/poseidon"
)

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
	rate := poseidon.NewKimchi().Rate()

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

func (p *Poseidon) HashWithPrefix(prefix string, data []byte) ([]byte, error) {

	dataFields, err := o1jsBytesToFields(data)
	if err != nil {
		return nil, err
	}

	hash, err := p.HashFieldsWithPrefix(prefix, dataFields...)
	if err != nil {
		return nil, err
	}

	return hash.Bytes(), nil
}

func (p *Poseidon) HashFieldsWithPrefix(
	prefix string,
	fieldsToHash ...*pasta.PallasBaseFieldElement,
) (*pasta.PallasBaseFieldElement, error) {
	field := pasta.NewPallasBaseField()
	rate := poseidon.NewKimchi().Rate()

	prefixField, err := prefixToField(prefix)
	if err != nil {
		return nil, err
	}

	p.hasher.Reset()

	prefixBlock := []*pasta.PallasBaseFieldElement{prefixField}
	for len(prefixBlock)%rate != 0 {
		prefixBlock = append(prefixBlock, field.Zero())
	}
	if err := p.hasher.Update(prefixBlock...); err != nil {
		return nil, err
	}

	if err := p.hasher.Update(padToRate(fieldsToHash, rate)...); err != nil {
		return nil, err
	}

	hash := p.hasher.Digest()
	p.hasher.Reset()
	return hash, nil
}
