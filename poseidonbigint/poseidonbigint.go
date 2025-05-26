package poseidonbigint

import "math/big"

// Go equivalent for: type GenericHashInput<Field> = { fields?: Field[]; packed?: [Field, number][] }
type PackedField struct {
	Field *big.Int
	Size  int
}

type HashInput struct {
	Fields []*big.Int
	Packed []PackedField
}

type HashInputHelpers struct{}

func (h HashInputHelpers) Empty() HashInput {
	return HashInput{
		Fields: nil,
		Packed: nil,
	}
}

func (h HashInputHelpers) Append(input1, input2 HashInput) HashInput {
	fields := append([]*big.Int{}, input1.Fields...)
	fields = append(fields, input2.Fields...)

	packed := append([]PackedField{}, input1.Packed...)
	packed = append(packed, input2.Packed...)

	return HashInput{
		Fields: fields,
		Packed: packed,
	}
}

func PackToFields(input HashInput) []*big.Int {
	fields := append([]*big.Int{}, input.Fields...)

	if len(input.Packed) == 0 {
		return fields
	}
	var packedBits []*big.Int
	currentPackedField := big.NewInt(0)
	currentSize := 0

	for _, p := range input.Packed {
		currentSize += p.Size
		if currentSize < 255 {
			shift := new(big.Int).Lsh(currentPackedField, uint(p.Size))
			currentPackedField = new(big.Int).Add(shift, p.Field)
		} else {
			packedBits = append(packedBits, new(big.Int).Set(currentPackedField))
			currentSize = p.Size
			currentPackedField = new(big.Int).Set(p.Field)
		}
	}
	packedBits = append(packedBits, currentPackedField)
	return append(fields, packedBits...)
}

type HashInputLegacy struct {
	Fields []*big.Int
	Bits   []bool
}

type HashInputLegacyHelpers struct{}

func (h HashInputLegacyHelpers) Empty() HashInputLegacy {
	return HashInputLegacy{
		Fields: nil,
		Bits:   nil,
	}
}
func (h HashInputLegacyHelpers) Bits(bits []bool) HashInputLegacy {
	return HashInputLegacy{
		Fields: nil,
		Bits:   bits,
	}
}
func (h HashInputLegacyHelpers) Append(i1, i2 HashInputLegacy) HashInputLegacy {
	fields := append([]*big.Int{}, i1.Fields...)
	fields = append(fields, i2.Fields...)

	bits := append([]bool{}, i1.Bits...)
	bits = append(bits, i2.Bits...)

	return HashInputLegacy{
		Fields: fields,
		Bits:   bits,
	}
}