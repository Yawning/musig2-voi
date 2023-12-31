// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: SSPL-1.0

package musig2

import (
	"errors"

	"gitlab.com/yawning/secp256k1-voi"
	"gitlab.com/yawning/secp256k1-voi/secec"
	"gitlab.com/yawning/secp256k1-voi/secec/bitcoin"
)

const (
	// PartialSignatureSize is the size of a byte-encoded PartialSignature
	// in bytes.
	PartialSignatureSize = 32 // secp256k1.ScalarSize

	tagSchnorrChallenge = "BIP0340/challenge"
)

var (
	errKeyNonceMismatch    = errors.New("musig2: secnonce for different signing key")
	errInvalidNumberOfSigs = errors.New("musig2: invalid number of signatures")
	errInvalidPartialSig   = errors.New("musig2: invalid partial signature")
	errNonceReuse          = errors.New("musig2: sign with invalidated nonce")
	errSigCheckFailed      = errors.New("musig2: failed to verify partial signature")
)

// PartialSignature is an un-aggregated partial signature.
type PartialSignature struct {
	s *secp256k1.Scalar
}

// Bytes returns the byte-encoding of the PartialSignature.
func (ps *PartialSignature) Bytes() []byte {
	return ps.s.Bytes()
}

// Verify verifies a PartialSignature.  This routine is only needed if
// identifiable aborts are required.
//
// WARNING: Partial signatures ARE NOT signatures.  An adversary is
// capable of forging a partial signature without knowing the private
// key for the claimed individual public key.
func (ps *PartialSignature) Verify(pk *secec.PublicKey, pubNonce *PublicNonce, aggPk *AggregatedPublicKey, aggNonce *AggregatedPublicNonce, msg []byte) bool {
	// Let (Q, gacc, _, b, R, e) = GetSessionValues(session_ctx);
	// fail if that fails
	b, R, e := getNonceValues(aggPk, aggNonce, msg)

	// Let s = int(psig); fail if s >= n
	// Let R*,1 = cpoint(pubnonce[0:33]), R*,2 = cpoint(pubnonce[33:66])
	// Let Re*' = R*,1 + b * R*,2
	effNonce := secp256k1.NewIdentityPoint().ScalarMult(b, pubNonce.r2)
	effNonce.Add(effNonce, pubNonce.r1)

	// Let effective nonce Re* = Re*' if has_even_y(R), otherwise let Re* = -Re*'
	effNonce.ConditionalNegate(effNonce, R.IsYOdd())

	// Let P = cpoint(pk); fail if that fails
	// Let a = GetSessionKeyAggCoeff(session_ctx, P)
	a, err := aggPk.getSessionKeyAggCoeff(pk)
	if err != nil {
		return false
	}

	// Let g = 1 if has_even_y(Q), otherwise let g = -1 mod n
	g := secp256k1.NewScalar().ConditionalSelect(scOne, scNegOne, aggPk.q.IsYOdd())

	// Let g' = g * gacc mod n (See Negation Of The Individual Public Key When Partially Verifying)
	gP := secp256k1.NewScalar().Multiply(g, aggPk.gacc)

	// Fail if s * G != Re* + e * a * g' * P
	// Return success iff no failure occurred before reaching this point.
	//
	// Rewriting for performance, Re* ?= s * G - e * a * g' * P
	gP.Negate(gP)
	negEAGp := secp256k1.NewScalar().Product(e, a, gP)
	maybeEffNonce := secp256k1.NewIdentityPoint().DoubleScalarMultBasepointVartime(ps.s, negEAGp, pk.Point())

	return maybeEffNonce.Equal(effNonce) == 1
}

// NewPartialSignature deserializes a PartialSignature from the byte-encoded
// form.
func NewPartialSignature(b []byte) (*PartialSignature, error) {
	if len(b) != PartialSignatureSize {
		return nil, errInvalidPartialSig
	}

	// Let s = int(psig); fail if s >= n
	sc, err := secp256k1.NewScalarFromCanonicalBytes((*[secp256k1.ScalarSize]byte)(b))
	if err != nil {
		return nil, errors.Join(errInvalidPartialSig, err)
	}

	return &PartialSignature{
		s: sc,
	}, nil
}

func getNonceValues(aggPk *AggregatedPublicKey, aggNonce *AggregatedPublicNonce, m []byte) (*secp256k1.Scalar, *secp256k1.Point, *secp256k1.Scalar) {
	// Let (Q, gacc, tacc) = keyagg_ctx_v
	qXBytes := aggPk.xBytes()

	// Let b = int(hashMuSig/noncecoef(aggnonce || xbytes(Q) || m)) mod n
	bBytes := taggedHash(
		tagNonceCoefficient,
		aggNonce.Bytes(), // aggnonce
		qXBytes,          // xbytes(Q)
		m,                // m
	)
	b, _ := secp256k1.NewScalarFromBytes((*[secp256k1.ScalarSize]byte)(bBytes))

	// Let R1 = cpoint_ext(aggnonce[0:33]), R2 = cpoint_ext(aggnonce[33:66]);
	// fail if that fails and blame nonce aggregator for invalid aggnonce.
	//
	// Let R' = R1 + b * R2
	rP := secp256k1.NewIdentityPoint().ScalarMult(b, aggNonce.r2)
	rP.Add(aggNonce.r1, rP)

	// If is_infinite(R'):
	// Let final nonce R = G (see Dealing with Infinity in Nonce Aggregation)
	// Else:
	// Let final nonce R = R'
	if rP.IsIdentity() != 0 {
		rP.Generator()
	}

	rXBytes, _ := rP.XBytes() // Can't fail, rP not infinity

	// Let e = int(hashBIP0340/challenge(xbytes(R) || xbytes(Q) || m)) mod n
	eBytes := taggedHash(
		tagSchnorrChallenge,
		rXBytes, // xbytes(R)
		qXBytes, // xbytes(Q)
		m,       // m
	)
	e, _ := secp256k1.NewScalarFromBytes((*[secp256k1.ScalarSize]byte)(eBytes))

	return b, rP, e // b, R, e
}

// Sign produces a PartialSignature over msg.  Regardless of this routine's
// success the provided SecretNonce will be cleared via Invalidate.
//
// WARNING: `secNonce` MUST NEVER be reused or exposed otherwise the signing
// key will be trivially compromised from partial signature(s).
func Sign(k *secec.PrivateKey, aggPk *AggregatedPublicKey, secNonce *SecretNonce, aggNonce *AggregatedPublicNonce, msg []byte) (*PartialSignature, error) {
	defer secNonce.Invalidate()

	// Let (Q, gacc, _, b, R, e) = GetSessionValues(session_ctx);
	// fail if that fails
	b, R, e := getNonceValues(aggPk, aggNonce, msg)

	// Let k1' = int(secnonce[0:32]), k2' = int(secnonce[32:64])
	// Fail if ki' = 0 or ki' >= n for i = 1..2
	// Let k1 = k1', k2 = k2' if has_even_y(R), otherwise let k1 = n - k1', k2 = n - k2'
	if !secNonce.IsValid() {
		return nil, errNonceReuse
	}
	isYOdd := R.IsYOdd()
	k1 := secp256k1.NewScalar().ConditionalNegate(secNonce.k1, isYOdd)
	k2 := secp256k1.NewScalar().ConditionalNegate(secNonce.k2, isYOdd)

	// Let d' = int(sk)
	// Fail if d' = 0 or d' >= n
	// Let P = d' * G
	// Let pk = cbytes(P)
	// Fail if pk != secnonce[64:97]
	if !secNonce.IsFor(k.PublicKey()) {
		return nil, errKeyNonceMismatch
	}

	// Let a = GetSessionKeyAggCoeff(session_ctx, P); fail if that fails
	a, err := aggPk.getSessionKeyAggCoeff(k.PublicKey())
	if err != nil {
		return nil, err
	}

	// Let g = 1 if has_even_y(Q), otherwise let g = -1 mod n
	g := secp256k1.NewScalar().ConditionalSelect(scOne, scNegOne, aggPk.q.IsYOdd())

	// Let d = g * gacc * d' mod n (See Negation Of The Secret Key When Signing)
	d := secp256k1.NewScalar().Product(g, aggPk.gacc, k.Scalar())

	// Let s = (k1 + b * k2 + e * a * d) mod n
	// Let psig = bytes(32, s)
	s := secp256k1.NewScalar().Sum(k1, secp256k1.NewScalar().Product(b, k2), secp256k1.NewScalar().Product(e, a, d))
	pSig := &PartialSignature{
		s: s,
	}

	// Let pubnonce = cbytes(k1'⋅G) || cbytes(k2'⋅G)
	// If PartialSigVerifyInternal(psig, pubnonce, pk, session_ctx) (see below) returns failure, fail
	if !pSig.Verify(k.PublicKey(), secNonce.PublicNonce(), aggPk, aggNonce, msg) {
		return nil, errSigCheckFailed
	}

	// Return partial signature psig
	return pSig, nil
}

// PartialSignatureAggregator accumulates PartialSignatures, before doing
// the final aggregation and generating a BIP-340 compatible Schnorr
// signature.
type PartialSignatureAggregator struct {
	r *secp256k1.Point
	s *secp256k1.Scalar

	u, expectedSigs uint64
}

// Add adds a PartialSignature to the signature aggregator.
func (agg *PartialSignatureAggregator) Add(pSig *PartialSignature) error {
	if agg.u+1 > agg.expectedSigs {
		return errInvalidNumberOfSigs
	}

	// For i = 1 .. u:
	//   Let s_i = int(psig_i);
	//   fail if s_i >= n and blame signer i for invalid partial signature.
	//
	// Let s = s_1 + ... + s_u + e * g * tacc mod n
	//
	// Note/yawning: agg.s is initialized to `e * g * tacc mod n`,
	// so all that's left to do is to add all the partial signatures.
	agg.s.Add(agg.s, pSig.s)
	agg.u++

	return nil
}

// Aggregate produces a BIP-340 compatible Schnorr signature.  This operation
// does not affect the state of the PartialSignatureAggregator.
func (agg *PartialSignatureAggregator) Aggregate() ([]byte, error) {
	if agg.u != agg.expectedSigs {
		return nil, errInvalidNumberOfSigs
	}

	// Return sig = xbytes(R) || bytes(32, s)
	rXBytes, _ := agg.r.XBytes() // Can't fail, R not infinity
	sig := make([]byte, 0, bitcoin.SchnorrSignatureSize)
	sig = append(sig, rXBytes...)
	sig = append(sig, agg.s.Bytes()...)

	return sig, nil
}

// NewPartialSignatureAggregator creates a PartialSignatureAggregator,
// initialized to gather partial signatures made with `(aggPk, aggNonce)`
// over `msg`.
func NewPartialSignatureAggregator(aggPk *AggregatedPublicKey, aggNonce *AggregatedPublicNonce, msg []byte) *PartialSignatureAggregator {
	// Let (Q, _, tacc, _, _, R, e) = GetSessionValues(session_ctx);
	// fail if that fails
	_, R, e := getNonceValues(aggPk, aggNonce, msg)

	// Let g = 1 if has_even_y(Q), otherwise let g = -1 mod n
	g := secp256k1.NewScalar().ConditionalSelect(scOne, scNegOne, aggPk.q.IsYOdd())

	// Let s = s_1 + ... + s_u + e * g * tacc mod n
	s := secp256k1.NewScalar().Product(e, g, aggPk.tacc)

	return &PartialSignatureAggregator{
		r:            R,
		s:            s,
		expectedSigs: uint64(len(aggPk.pks)),
	}
}
