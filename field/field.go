package field

import (
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/node101-io/mina-signer-go/errors"
)

type Field struct {
	field *pasta.PallasBaseField
}

func NewField() *Field {
	return &Field{
		field: pasta.NewPallasBaseField(),
	}
}

func (f *Field) ElementSize() int {
	if f == nil || f.field == nil {
		return 0
	}

	return f.field.ElementSize()
}

func (f *Field) Zero() *FieldElement {
	if f == nil || f.field == nil {
		return nil
	}

	return &FieldElement{
		element: f.field.Zero(),
	}
}

func (f *Field) One() *FieldElement {
	if f == nil || f.field == nil {
		return nil
	}

	return &FieldElement{
		element: f.field.One(),
	}
}

func (f *Field) FromUint64(v uint64) *FieldElement {
	if f == nil || f.field == nil {
		return nil
	}

	return &FieldElement{
		element: f.field.FromUint64(v),
	}
}

func (f *Field) FromBytes(b []byte) (*FieldElement, error) {
	if f == nil || f.field == nil {
		return nil, errors.ErrNilField
	}

	element, err := f.field.FromBytes(b)
	if err != nil {
		return nil, err
	}

	return &FieldElement{
		element: element,
	}, nil
}

func (f *Field) FromBytesBEReduce(b []byte) (*FieldElement, error) {
	if f == nil || f.field == nil {
		return nil, errors.ErrNilField
	}

	element, err := f.field.FromBytesBEReduce(b)
	if err != nil {
		return nil, err
	}

	return &FieldElement{
		element: element,
	}, nil
}
