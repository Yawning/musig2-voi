package musig2

import (
	"errors"

	"gitlab.com/yawning/secp256k1-voi"
)

const (
	PartialSignatureSize = 32 // secp256k1.ScalarSize

	tagSchnorrChallenge = "BIP0340/challenge"
)

var (
	errKeyNonceMismatch    = errors.New("musig2: secnonce for different private key")
	errPublicKeyNotInAgg   = errors.New("musig2: public key not part of aggregate key")
	errInvalidNumberOfSigs = errors.New("musig2: invalid number of signatures")
	errInvalidPartialSig   = errors.New("musig2: invalid partial signature")
)

type PartialSignature struct {
	s *secp256k1.Scalar
}

func (ps *PartialSignature) Bytes() []byte {
	return ps.s.Bytes()
}

func NewPartialSignature(b []byte) (*PartialSignature, error) {
	if len(b) != PartialSignatureSize {
		return nil, errInvalidPartialSig
	}

	sc, err := secp256k1.NewScalarFromCanonicalBytes((*[secp256k1.ScalarSize]byte)(b))
	if err != nil {
		return nil, errors.Join(errInvalidPartialSig, err)
	}

	return &PartialSignature{
		s: sc,
	}, nil
}

func getNonceValues(keyCtx *KeyAggContext, aggNonce *PublicNonce, m []byte) (*secp256k1.Scalar, *secp256k1.Point, *secp256k1.Scalar) {
	// Let (Q, gacc, tacc) = keyagg_ctx_v
	qXBytes := keyCtx.XBytes()

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

func (ctx *KeyAggContext) getSessionKeyAggCoeff(pk *PublicKey) *secp256k1.Scalar {
	// Fail if pk not in pk_1..u
	var ok bool
	for _, v := range ctx.pks {
		if ok = v.Equal(pk); ok {
			break
		}
	}
	if !ok {
		return nil
	}

	return keyAggCoeff(ctx.pks, pk)
}

func (k *PrivateKey) Sign(keyCtx *KeyAggContext, secNonce *SecretNonce, aggNonce *PublicNonce, m []byte) (*PartialSignature, error) {
	// Let (Q, gacc, _, b, R, e) = GetSessionValues(session_ctx);
	// fail if that fails
	b, R, e := getNonceValues(keyCtx, aggNonce, m)

	// Let k1' = int(secnonce[0:32]), k2' = int(secnonce[32:64])
	// Fail if ki' = 0 or ki' >= n for i = 1..2
	// Let k1 = k1', k2 = k2' if has_even_y(R), otherwise let k1 = n - k1', k2 = n - k2'
	isYOdd := R.IsYOdd()
	k1 := secp256k1.NewScalar().ConditionalNegate(secNonce.k1, isYOdd)
	k2 := secp256k1.NewScalar().ConditionalNegate(secNonce.k2, isYOdd)

	// Let d' = int(sk)
	// Fail if d' = 0 or d' >= n
	// Let P = d' * G
	// Let pk = cbytes(P)
	// Fail if pk != secnonce[64:97]
	if k.pk.p.Equal(secNonce.pk) != 1 {
		return nil, errKeyNonceMismatch
	}

	// Let a = GetSessionKeyAggCoeff(session_ctx, P); fail if that fails
	a := keyCtx.getSessionKeyAggCoeff(k.pk)
	if a == nil {
		return nil, errPublicKeyNotInAgg
	}

	// XXX/yawning: Obliterate secNonce or something

	// Let g = 1 if has_even_y(Q), otherwise let g = -1 mod n
	g := secp256k1.NewScalar().ConditionalSelect(scOne, scNegOne, keyCtx.q.IsYOdd())

	// Let d = g * gacc * d' mod n (See Negation Of The Secret Key When Signing)
	d := secp256k1.NewScalar().Product(g, keyCtx.gacc, k.dPrime)

	// Let s = (k1 + b * k2 + e * a * d) mod n
	// Let psig = bytes(32, s)
	s := secp256k1.NewScalar().Sum(k1, secp256k1.NewScalar().Product(b, k2), secp256k1.NewScalar().Product(e, a, d))

	// Let pubnonce = cbytes(k1'⋅G) || cbytes(k2'⋅G)
	// If PartialSigVerifyInternal(psig, pubnonce, pk, session_ctx) (see below) returns failure, fail

	// Return partial signature psig
	return &PartialSignature{
		s: s,
	}, nil
}

// TODO: PartialSigVerify or whatever, who cares.

func PartialSigAgg(keyCtx *KeyAggContext, aggNonce *PublicNonce, m []byte, pSigs []*PartialSignature) ([]byte, error) {
	// Let (Q, _, tacc, _, _, R, e) = GetSessionValues(session_ctx);
	// fail if that fails
	_, R, e := getNonceValues(keyCtx, aggNonce, m)

	// For i = 1 .. u:
	// Let s_i = int(psig_i);
	// fail if s_i >= n and blame signer i for invalid partial signature.
	if len(pSigs) != len(keyCtx.pks) {
		return nil, errInvalidNumberOfSigs
	}

	// Let g = 1 if has_even_y(Q), otherwise let g = -1 mod n
	g := secp256k1.NewScalar().ConditionalSelect(scOne, scNegOne, keyCtx.q.IsYOdd())

	// Let s = s_1 + ... + s_u + e * g * tacc mod n
	s := secp256k1.NewScalar().Product(e, g, keyCtx.tacc)
	for _, pSig := range pSigs {
		s.Add(s, pSig.s)
	}

	// Return sig = xbytes(R) || bytes(32, s)
	rXBytes, _ := R.XBytes()   // Can't fail, R not infinity
	sig := make([]byte, 0, 64) // XXX/yawning: magic number
	sig = append(sig, rXBytes...)
	sig = append(sig, s.Bytes()...)

	return sig, nil
}
