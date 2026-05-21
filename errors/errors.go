package errors

import "errors"

var (
	ErrNilSignature = errors.New("nil signature")

	ErrInvalidSignatureLength = errors.New("invalid signature length")

	ErrNilPublicKey = errors.New("nil public key")

	ErrNilPrivateKey = errors.New("nil private key")

	ErrInternal = errors.New("internal error")

	ErrNilHasher = errors.New("nil hasher")

	ErrNilMerkleList = errors.New("nil merkle list")

	ErrNilMessage = errors.New("nil message")

	ErrNilPoseidon = errors.New("nil poseidon")

	ErrNilAddress = errors.New("nil address")

	ErrInvalidAddressLength = errors.New("invalid address length")
)
