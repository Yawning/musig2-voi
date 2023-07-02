package musig2

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/yawning/secp256k1-voi/secec"
)

func testNonceGenVectors(t *testing.T) {
	// Sigh: This is different enough from every other test
	// vector format that it needs special treatment.

	type testCase struct {
		RandP            string  `json:"rand_"`
		PrivateKey       string  `json:"sk"`
		PublicKey        string  `json:"pk"`
		AggPk            string  `json:"aggpk"`
		Msg              *string `json:"msg"`
		ExtraIn          string  `json:"extra_in"`
		ExpectedSecNonce string  `json:"expected_secnonce"`
		ExpectedPubNonce string  `json:"expected_pubnonce"`
	}

	type testCases struct {
		TestCases []testCase `json:"test_cases"`
	}

	var testVectors testCases
	unpackTestVectors(t, "testdata/nonce_gen_vectors.json", &testVectors)

	for i := range testVectors.TestCases {
		vec := &testVectors.TestCases[i]
		t.Run(fmt.Sprintf("Case %d", i), func(t *testing.T) {
			randP := mustUnhex(vec.RandP)

			var (
				sk                  *secec.PrivateKey
				pk                  *secec.PublicKey
				err                 error
				aggpk, msg, extraIn []byte
			)
			if x := vec.PrivateKey; x != "" {
				sk, err = secec.NewPrivateKey(mustUnhex(x))
				require.NoError(t, err, "NewPrivateKey")
			}
			pk, err = secec.NewPublicKey(mustUnhex(vec.PublicKey))
			require.NoError(t, err, "NewPublicKey")

			if x := vec.AggPk; x != "" {
				aggpk = mustUnhex(x)
			}
			if vec.Msg != nil {
				msg = []byte{} // "" != nil
				if x := *vec.Msg; len(x) > 0 {
					msg = mustUnhex(x)
				}
			}
			if x := vec.ExtraIn; x != "" {
				extraIn = mustUnhex(x)
			}

			secnonce, pubnonce, err := nonceGen(pk, sk, aggpk, msg, extraIn, randP)
			require.NoError(t, err, "nonceGen")

			expectedPub := mustUnhex(vec.ExpectedPubNonce)
			require.EqualValues(t, expectedPub, pubnonce.Bytes(), "pubnonce")

			expectedSec := mustUnhex(vec.ExpectedSecNonce)
			require.EqualValues(t, expectedSec, secnonce.Bytes(), "secnonce")
		})
	}
}

func testNonceAggVectors(t *testing.T) {
	var testVectors tvHeader
	unpackTestVectors(t, "testdata/nonce_agg_vectors.json", &testVectors)

	for i := range testVectors.Valid {
		vec := &testVectors.Valid[i]
		t.Run(fmt.Sprintf("Valid %d", i), func(t *testing.T) {
			if vec.Comment != "" {
				t.Log(vec.Comment)
			}

			aggNonce := testVectors.AggNonce(t, vec.PNonceIndices)
			require.Equal(t, vec.Expected(), aggNonce.Bytes())
		})
	}

	for i := range testVectors.Error {
		vec := &testVectors.Error[i]
		t.Run(fmt.Sprintf("Error %d", i), func(t *testing.T) {
			if vec.Comment != "" {
				t.Logf("%s", vec.Comment)
			}

			tvNonces, errs := testVectors.PubNonces()

			// If the test case failure is due to an invalid contribution
			// this is something that our implementation catches when the
			// public nonce is deserialized.
			if vec.Error.Type == typeInvalidContribution {
				require.Equal(t, contribPubNonce, vec.Error.Contrib)
				idx := vec.PNonceIndices[*vec.Error.Signer]
				require.Nil(t, tvNonces[idx])
				require.Error(t, errs[idx])
				return
			}

			t.Fatalf("unsupported test case type: '%s'", vec.Error.Type)
		})
	}
}
