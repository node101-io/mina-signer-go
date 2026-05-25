package address

import (
	"github.com/bronlabs/bron-crypto/pkg/base/base58"
	"github.com/bronlabs/bron-crypto/pkg/base/curves/pasta"
	"github.com/bronlabs/bron-crypto/pkg/signatures/schnorrlike/mina"
	"github.com/node101-io/mina-signer-go/errors"
)

type Address struct {
	addr string
}

func NewAddress(addr string) *Address {
	return &Address{
		addr: addr,
	}
}

func (addr *Address) String() string {
	if addr == nil {
		return ""
	}
	return addr.addr
}

func (addr *Address) Marshal() ([]byte, error) {

	if addr == nil {
		return nil, errors.ErrNilAddress
	}

	pk, err := mina.DecodePublicKey(base58.Base58(addr.addr))
	if err != nil {
		return nil, err
	}

	return pk.Value().Bytes(), nil
}

func (addr *Address) Unmarshal(encoded []byte) error {

	if len(encoded) != mina.PublicKeySize {
		return errors.ErrInvalidAddressLength
	}

	point, err := pasta.NewPallasCurve().FromBytes(encoded)
	if err != nil {
		return err
	}

	pk, err := mina.NewPublicKey(point)
	if err != nil {
		return err
	}

	address, err := mina.EncodePublicKey(pk)
	if err != nil {
		return err
	}

	addr.addr = string(address)

	return nil
}
