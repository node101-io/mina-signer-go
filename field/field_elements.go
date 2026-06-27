package field

import (
	"bytes"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
)

type FieldElement struct {
	element *pasta.PallasBaseFieldElement
}

func NewFieldElement(element []byte) (*FieldElement, error) {
	field := pasta.NewPallasBaseField()

	fieldElement, err := field.FromBytes(element)
	if err != nil {
		return nil, err
	}

	return &FieldElement{
		element: fieldElement,
	}, nil
}

func (f *FieldElement) IsValid() bool {
	return f != nil && f.element != nil
}

func (f *FieldElement) Bytes() []byte {
	if !f.IsValid() {
		return nil
	}

	return bytes.Clone(f.element.Bytes())
}

func (f *FieldElement) Clone() *FieldElement {
	if !f.IsValid() {
		return nil
	}

	return &FieldElement{
		element: f.element.Clone(),
	}
}

func (f *FieldElement) Equal(other *FieldElement) bool {
	if !f.IsValid() || !other.IsValid() {
		return false
	}

	return f.element.Equal(other.element)
}

func (f *FieldElement) IsZero() bool {
	if !f.IsValid() {
		return false
	}

	return f.element.IsZero()
}

func (f *FieldElement) String() string {
	if !f.IsValid() {
		return ""
	}

	return f.element.Cardinal().Big().String()
}
