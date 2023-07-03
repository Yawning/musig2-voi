// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: SSPL-1.0

package musig2

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func testSignVectors(t *testing.T) {
	var testVectors struct {
		tvHeader
		SignError []tvErrorCase `json:"sign_error_test_cases"`
	}
	unpackTestVectors(t, "testdata/sign_verify_vectors.json", &testVectors)

	for i := range testVectors.Valid {
		vec := &testVectors.Valid[i]
		t.Run(fmt.Sprintf("Valid %d", i), func(t *testing.T) {
			if vec.Comment != "" {
				t.Log(vec.Comment)
			}

			sk := testVectors.SecKey(t)

			pkAggregator := testVectors.PublicKeyAggregator(t, vec.KeyIndices)
			aggPk, err := pkAggregator.Aggregate()
			require.NoError(t, err)

			msg := testVectors.Messages()[vec.MsgIndex]
			require.NotNil(t, msg)

			// WARNING: Don't ever do this. Tbh, including this in test
			// vectors/test cases is fucking moronic, despite the warning
			// in the reference python code.
			//
			// I get that it's the crypto winter, but I didn't know that
			// things were so tight that they can't spare (at most)
			// 97-bytes per valid test case.
			secNonces, _ := testVectors.SecNonces()
			secNonce := secNonces[0].UnsafeClone()

			nonceAggregator := testVectors.PublicNonceAggregator(t, vec.NonceIndices)
			aggNonce, err := nonceAggregator.Aggregate()
			require.NoError(t, err)

			aggNonces, _ := testVectors.AggNonces()
			expectedAggNonce := aggNonces[vec.AggNonceIndex]
			require.EqualValues(t, expectedAggNonce.Bytes(), aggNonce.Bytes())

			partialSig, err := Sign(sk, aggPk, secNonce, aggNonce, msg)
			require.NoError(t, err, "Sign")
			require.EqualValues(t, vec.Expected(), partialSig.Bytes())

			// This is done implicitly, but do it explicitly as well.
			ok := partialSig.Verify(sk.PublicKey(), secNonce.PublicNonce(), aggPk, aggNonce, msg)
			require.True(t, ok)

			// Check that the secNonce got invalidated.
			require.False(t, secNonce.IsValid())
		})
	}

	for i := range testVectors.SignError {
		vec := &testVectors.SignError[i]
		t.Run(fmt.Sprintf("Error %d", i), func(t *testing.T) {
			if vec.Comment != "" {
				t.Log(vec.Comment)
			}

			sk := testVectors.SecKey(t)

			if vec.Error.Is(typeInvalidContribution, contribPubKey) {
				pubKeys, errs := testVectors.PubKeys()
				t.Log(pubKeys)

				idx := vec.KeyIndices[*vec.Error.Signer]
				require.Nil(t, pubKeys[idx])
				require.Error(t, errs[idx])
				return
			}

			aggregator := testVectors.PublicKeyAggregator(t, vec.KeyIndices)
			aggPk, err := aggregator.Aggregate()
			require.NoError(t, err)

			msg := testVectors.Messages()[vec.MsgIndex]
			require.NotNil(t, msg)

			// Sigh, just... no (See the warning in the successful case).
			secNonces, errs := testVectors.SecNonces()
			secNonce := secNonces[vec.SecNonceIndex]
			if secNonce == nil {
				require.Equal(t, typeValue, vec.Error.Type)
				require.ErrorIs(t, errs[vec.SecNonceIndex], errKIsZero)
				return
			}
			secNonce = secNonce.UnsafeClone()

			aggNonces, errs := testVectors.AggNonces()
			if vec.Error.Is(typeInvalidContribution, contribAggNonce) {
				idx := vec.AggNonceIndex
				require.Nil(t, aggNonces[idx])
				require.Error(t, errs[idx])
				return
			}
			aggNonce := aggNonces[vec.AggNonceIndex]

			partialSig, err := Sign(sk, aggPk, secNonce, aggNonce, msg)
			require.Error(t, err, "Sign")
			require.Nil(t, partialSig)

			// Check that the secNonce got invalidated, the fast way.
			require.False(t, secNonce.IsValid())
		})
	}
}

func testPartialSigVerifyVectors(t *testing.T) {
	// We are only concerned about the various failures, as the
	// successful case is covered by the Sign tests.

	var testVectors struct {
		tvHeader
		Fail  []tvErrorCase `json:"verify_fail_test_cases"`
		Error []tvErrorCase `json:"verify_error_test_cases"`
	}
	unpackTestVectors(t, "testdata/sign_verify_vectors.json", &testVectors)

	pubKeys, pubKeysErrs := testVectors.PubKeys()
	pubNonces, pubNoncesErrs := testVectors.PubNonces()

	for i := range testVectors.Fail {
		vec := &testVectors.Fail[i]
		t.Run(fmt.Sprintf("Fail %d", i), func(t *testing.T) {
			if vec.Comment != "" {
				t.Log(vec.Comment)
			}

			aggregator := testVectors.PublicKeyAggregator(t, vec.KeyIndices)
			aggPk, err := aggregator.Aggregate()
			require.NoError(t, err)

			msg := testVectors.Messages()[vec.MsgIndex]
			require.NotNil(t, msg)

			nonceAggregator := testVectors.PublicNonceAggregator(t, vec.NonceIndices)
			aggNonce, err := nonceAggregator.Aggregate()
			require.NoError(t, err)

			idx := vec.SignerIndex
			pubKey, pubNonce := pubKeys[vec.KeyIndices[idx]], pubNonces[vec.NonceIndices[idx]]

			partialSig, err := NewPartialSignature(mustUnhex(vec.Sig))

			// Is it too much to ask for test cases to consistently include
			// the "error" sub-structure.
			switch i {
			case 2:
				// Signature fails to deserialize.
				require.Nil(t, partialSig)
				require.ErrorIs(t, err, errInvalidPartialSig)
			default:
				require.NoError(t, err)
				ok := partialSig.Verify(pubKey, pubNonce, aggPk, aggNonce, msg)
				require.False(t, ok)
			}
		})
	}

	for i := range testVectors.Error {
		vec := &testVectors.Error[i]
		t.Run(fmt.Sprintf("Error %d", i), func(t *testing.T) {
			if vec.Comment != "" {
				t.Log(vec.Comment)
			}

			// These are just deserialization failures.
			require.Equal(t, typeInvalidContribution, vec.Error.Type)
			idx := vec.SignerIndex
			pubKeyErr, pubNonceErr := pubKeysErrs[vec.KeyIndices[idx]], pubNoncesErrs[vec.NonceIndices[idx]]
			t.Log(pubKeyErr)
			t.Log(pubNonceErr)
			switch vec.Error.Contrib {
			case contribPubKey:
				require.Error(t, pubKeyErr)
			case contribPubNonce:
				require.Error(t, pubNonceErr)
			default:
				t.Fatalf("unsupported test case contrib: '%s'", vec.Error.Contrib)
			}
		})
	}
}

func testPartialSigAggVectors(t *testing.T) {
	var testVectors tvHeader
	unpackTestVectors(t, "testdata/sig_agg_vectors.json", &testVectors)

	msg := testVectors.Msg()

	for i := range testVectors.Valid {
		vec := &testVectors.Valid[i]
		t.Run(fmt.Sprintf("Valid %d", i), func(t *testing.T) {
			if vec.Comment != "" {
				t.Log(vec.Comment)
			}

			pkAggregator := testVectors.PublicKeyAggregator(t, vec.KeyIndices)
			aggPk, err := pkAggregator.Aggregate()
			require.NoError(t, err)

			tweaks := testVectors.Tweaks()
			for ii, idx := range vec.TweakIndices {
				tweak, isXOnly := tweaks[idx], vec.IsXOnly[ii]
				err := aggPk.ApplyTweak(tweak, isXOnly)
				require.NoError(t, err, "ApplyTweak")
			}

			nonceAggregator := testVectors.PublicNonceAggregator(t, vec.NonceIndices)
			aggNonce, err := nonceAggregator.Aggregate()
			require.NoError(t, err)

			expectedAggNonce := vec.AggNonce(t)
			require.EqualValues(t, expectedAggNonce.Bytes(), aggNonce.Bytes())

			sigAggregator := NewPartialSignatureAggregator(aggPk, aggNonce, msg)
			hdrPSigs, errs := testVectors.PartialSigs()
			for _, idx := range vec.PSigIndices {
				require.NoError(t, errs[idx])
				err = sigAggregator.Add(hdrPSigs[idx])
				require.NoError(t, err)
			}

			sig, err := sigAggregator.Aggregate()
			require.NoError(t, err)

			// So, the claim/whole point of this MuSig2 nonsense is
			// that aggregated signatures are compatible with BIP-340
			// Schnorr signatures, so test that as well.

			ok := aggPk.Schnorr().Verify(msg, sig)
			require.True(t, ok, "SchnorrPublicKey.Verify")
		})
	}

	for i := range testVectors.Error {
		vec := &testVectors.Error[i]
		t.Run(fmt.Sprintf("Error %d", i), func(t *testing.T) {
			// There's only one test case, and it's signature s11n
			// related. Naturally, unlike the other test cases,
			// the `error` is missing `contrib`, because fuck you.
			require.True(t, vec.Error.Is(typeInvalidContribution, ""))
			hdrPSigs, errs := testVectors.PartialSigs()
			idx := vec.PSigIndices[*vec.Error.Signer]
			require.Nil(t, hdrPSigs[idx])
			require.Error(t, errs[idx])
		})
	}
}
