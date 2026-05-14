package errors

import "errors"

var ErrNilSignature = errors.New("nil signature")
var ErrInvalidSignatureLenght error = errors.New("invalid signature lenght")

var ErrNilPublicKey = errors.New("nil public key")

var ErrNilPrivateKey = errors.New("nil private key")
var ErrInternal = errors.New("internal error")
