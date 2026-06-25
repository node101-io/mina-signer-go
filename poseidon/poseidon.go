package poseidon

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/hashing/poseidon"
	"github.com/node101-io/mina-signer-go/errors"
	minafield "github.com/node101-io/mina-signer-go/field"
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

	if p == nil {
		return nil, errors.ErrNilPoseidon
	}
	if p.hasher == nil {
		return nil, errors.ErrNilHasher
	}

	p.hasher.Reset()
	defer p.hasher.Reset()

	field := pasta.NewPallasBaseField()
	rate := p.hasher.Rate()

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
	return p.hasher.Sum(nil), nil
}

func (p *Poseidon) HashFieldElements(fieldsToHash ...*minafield.FieldElement) (*minafield.FieldElement, error) {

	if p == nil {
		return nil, errors.ErrNilPoseidon
	}

	if p.hasher == nil {
		return nil, errors.ErrNilHasher
	}

	p.hasher.Reset()
	defer p.hasher.Reset()

	raw, err := toPastaFieldElements(fieldsToHash...)
	if err != nil {
		return nil, err
	}

	if err := p.hasher.Update(padToRate(raw, p.hasher.Rate())...); err != nil {
		return nil, err
	}

	hash := p.hasher.Digest().Bytes()

	return minafield.NewField().FromBytes(hash)
}

func (p *Poseidon) HashWithPrefix(prefix string, data []byte) ([]byte, error) {
	dataFields, err := o1jsBytesToFields(data)
	if err != nil {
		return nil, err
	}

	return p.HashFieldsWithPrefix(prefix, dataFields...)
}

func (p *Poseidon) HashFieldsWithPrefix(
	prefix string,
	fieldsToHash ...*pasta.PallasBaseFieldElement,
) ([]byte, error) {

	if p == nil {
		return nil, errors.ErrNilPoseidon
	}
	if p.hasher == nil {
		return nil, errors.ErrNilHasher
	}

	p.hasher.Reset()
	defer p.hasher.Reset()

	field := pasta.NewPallasBaseField()
	rate := p.hasher.Rate()

	prefixField, err := prefixToField(prefix)
	if err != nil {
		return nil, err
	}

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

	return p.hasher.Digest().Bytes(), nil
}

func (p *Poseidon) HashFieldElementsWithPrefix(
	prefix string,
	fieldsToHash ...*minafield.FieldElement,
) (*minafield.FieldElement, error) {

	raw, err := toPastaFieldElements(fieldsToHash...)
	if err != nil {
		return nil, err
	}

	hash, err := p.HashFieldsWithPrefix(prefix, raw...)
	if err != nil {
		return nil, err
	}

	return minafield.NewField().FromBytes(hash)
}

func toPastaFieldElements(xs ...*minafield.FieldElement) ([]*pasta.PallasBaseFieldElement, error) {
	field := pasta.NewPallasBaseField()
	out := make([]*pasta.PallasBaseFieldElement, 0, len(xs))

	for _, x := range xs {
		if !x.IsValid() {
			return nil, errors.ErrNilField
		}

		raw, err := field.FromBytes(x.Bytes())
		if err != nil {
			return nil, err
		}
		out = append(out, raw)
	}

	return out, nil
}
