package poseidon

import (
	"fmt"

	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
)

const (
	o1jsChunkSize = 31
	o1jsStopByte  = byte(0x01)
)

func littleEndianChunkToField(
	field *pasta.PallasBaseField,
	chunk []byte,
	addStopByte bool,
) (*pasta.PallasBaseFieldElement, error) {
	var be [32]byte

	for i, b := range chunk {
		be[31-i] = b
	}

	if addStopByte {
		be[31-len(chunk)] = o1jsStopByte
	}

	return field.FromBytes(be[:])
}

func o1jsBytesToFields(data []byte) ([]*pasta.PallasBaseFieldElement, error) {
	field := pasta.NewPallasBaseField()
	out := make([]*pasta.PallasBaseFieldElement, 0, len(data)/o1jsChunkSize+1)

	for len(data) >= o1jsChunkSize {
		x, err := littleEndianChunkToField(field, data[:o1jsChunkSize], false)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
		data = data[o1jsChunkSize:]
	}

	// final chunk always gets the stop byte, even if data is empty
	x, err := littleEndianChunkToField(field, data, true)
	if err != nil {
		return nil, err
	}
	out = append(out, x)

	return out, nil
}

func reverseInPlace(b []byte) {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
}
func prefixToField(prefix string) (*pasta.PallasBaseFieldElement, error) {
	if len(prefix)*8 >= 255 {
		return nil, fmt.Errorf("prefix too long")
	}
	for i := 0; i < len(prefix); i++ {
		if prefix[i] > 0x7f {
			return nil, fmt.Errorf("prefix must be ASCII")
		}
	}

	be := make([]byte, 32)
	copy(be, []byte(prefix))
	reverseInPlace(be)

	return pasta.NewPallasBaseField().FromBytes(be)
}

func padToRate(xs []*pasta.PallasBaseFieldElement, rate int) []*pasta.PallasBaseFieldElement {
	field := pasta.NewPallasBaseField()
	out := append([]*pasta.PallasBaseFieldElement(nil), xs...)
	if len(out) == 0 {
		out = append(out, field.Zero())
	}
	for len(out)%rate != 0 {
		out = append(out, field.Zero())
	}
	return out
}
