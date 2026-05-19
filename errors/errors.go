package errors

import "errors"

var ErrNilSignature = errors.New("nil signature")
var ErrInvalidSignatureLength error = errors.New("invalid signature length")

var ErrNilPublicKey = errors.New("nil public key")

var ErrNilPrivateKey = errors.New("nil private key")
var ErrInternal = errors.New("internal error")

var ErrNilHasher = errors.New("nil hasher")

var ErrNilMerkleList = errors.New("nil merkle list")

var ErrNilMessage = errors.New("nil message")
