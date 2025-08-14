package poseidonbigint

import (
	"math/big"

	"github.com/node101-io/mina-signer-go/field"
)

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

// PackToFieldsLegacy mirrors the TS version:
//
//	function packToFieldsLegacy({ fields, bits }: HashInputLegacy) {
//	  let packedFields = [];
//	  while (bits.length > 0) {
//	    let fieldBits = bits.splice(0, sizeInBits - 1);
//	    let field = Field.fromBits(fieldBits);
//	    packedFields.push(field);
//	  }
//	  return fields.concat(packedFields);
//	}
func PackToFieldsLegacy(input HashInputLegacy) []*big.Int {
	// copy to avoid mutating caller slices
	fields := append([]*big.Int{}, input.Fields...)
	bits := append([]bool{}, input.Bits...)

	// sizeInBits = log2(p) (Pallas taban alanı için 255)
	// TS: sizeInBits - 1 (254) kullanılıyor — overflow güvenliği için
	chunkSize := field.Fp.SizeInBits - 1 // 254

	for len(bits) > 0 {
		take := chunkSize
		if len(bits) < take {
			take = len(bits)
		}
		fieldBits := bits[:take]
		bits = bits[take:]

		// TS: Field.fromBits(fieldBits) == fromBytes(bitsToBytes(fieldBits))
		// bitsToBytes: LSB-first -> little-endian byte dizisi
		b := bitsToBytesLSBFirst(fieldBits)

		// Go: FromBytes little-endian bekler, içeride big-endian’a çevirip mod p alır
		x := field.Fp.FromBytes(b)
		fields = append(fields, x)
	}
	return fields
}

// bitsToBytesLSBFirst packs a boolean bit-slice into little-endian bytes,
// where bits[i] corresponds to bit (i % 8) of byte at index i/8 (LSB-first per byte).
func bitsToBytesLSBFirst(bits []bool) []byte {
	if len(bits) == 0 {
		return []byte{}
	}
	n := (len(bits) + 7) / 8
	out := make([]byte, n)
	for i, bit := range bits {
		if bit {
			out[i/8] |= 1 << uint(i%8)
		}
	}
	return out
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

// stringToBytes converts a string to a byte array.
func stringToBytes(s string) []byte {
	return []byte(s)
}

// bytesToBits converts a byte array to a slice of booleans, where each byte is split into 8 bits (LSB-first).
func bytesToBits(bs []byte) []bool {
	out := make([]bool, 0, len(bs)*8)
	for _, b := range bs {
		x := b
		for i := 0; i < 8; i++ {
			out = append(out, (x&1) == 1) // LSB-first
			x >>= 1
		}
	}
	return out
}

// Reverse the bits in place
func reverseInPlace(b []bool) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}

// StringToInput converts a string to a HashInputLegacy.
func StringToInput(s string) HashInputLegacy {
	bytes := stringToBytes(s)

	// Toplam bit kapasitesi: her bayt için 8 bit.
	bits := make([]bool, 0, len(bytes)*8)
	for _, b := range bytes {
		perByte := bytesToBits([]byte{b}) // 8 adet bool, LSB-first
		reverseInPlace(perByte)           // JS'deki .reverse() ile birebir
		bits = append(bits, perByte...)
	}

	return (HashInputLegacyHelpers{}).Bits(bits)
}
