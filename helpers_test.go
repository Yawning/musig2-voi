package musig2

import (
	"encoding/hex"
	"errors"

	"gitlab.com/yawning/secp256k1-voi"
)

const secretNonceSize = 97

func (pk *PublicKey) String() string {
	return hex.EncodeToString(pk.pBytes)
}

func (n *SecretNonce) Bytes() []byte {
	b := make([]byte, 0, secretNonceSize)
	b = append(b, n.k1.Bytes()...)
	b = append(b, n.k2.Bytes()...)
	b = append(b, n.pk.CompressedBytes()...)
	return b
}

func newSecretNonce(b []byte) (*SecretNonce, error) {
	if len(b) != secretNonceSize {
		return nil, errors.New("musig2: invalid secret nonce")
	}

	k1Bytes := (*[secp256k1.ScalarSize]byte)(b[:32])
	k2Bytes := (*[secp256k1.ScalarSize]byte)(b[32:64])
	pkBytes := b[64:]

	k1, err := secp256k1.NewScalarFromCanonicalBytes(k1Bytes)
	if err != nil {
		return nil, err
	}
	k2, err := secp256k1.NewScalarFromCanonicalBytes(k2Bytes)
	if err != nil {
		return nil, err
	}
	if k1.IsZero() != 0 || k2.IsZero() != 0 {
		return nil, errKIsZero
	}
	pk, err := secp256k1.NewIdentityPoint().SetCompressedBytes(pkBytes)
	if err != nil {
		return nil, err
	}

	return &SecretNonce{
		k1: k1,
		k2: k2,
		pk: pk,
	}, nil
}

func mustUnhex(str string) []byte {
	b, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return b
}
