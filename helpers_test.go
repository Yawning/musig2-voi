// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: SSPL-1.0

package musig2

import (
	"encoding/hex"

	"gitlab.com/yawning/secp256k1-voi"
)

func (n *SecretNonce) UnsafeClone() *SecretNonce {
	// This routine shouldn't exist, but the BIP-supplied test cases
	// reuse secnonce.
	child := &SecretNonce{
		k1: secp256k1.NewScalarFrom(n.k1),
		k2: secp256k1.NewScalarFrom(n.k2),
		pk: secp256k1.NewPointFrom(n.pk),
	}
	child.publicNonce = child.genPublicNonce()

	return child
}

func mustUnhex(str string) []byte {
	b, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return b
}
