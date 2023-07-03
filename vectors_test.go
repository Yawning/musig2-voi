// Copyright (c) 2023 Yawning Angel
//
// SPDX-License-Identifier: SSPL-1.0

package musig2

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"gitlab.com/yawning/secp256k1-voi/secec"
)

const (
	typeInvalidContribution = "invalid_contribution"
	typeValue               = "value"

	contribPubKey   = "pubkey"
	contribPubNonce = "pubnonce"
	contribAggNonce = "aggnonce"
)

func TestVectors(t *testing.T) {
	t.Run("Key/Sort", testKeySortVectors)
	t.Run("Key/Agg", testKeyAggVectors)
	t.Run("Nonce/Gen", testNonceGenVectors)
	t.Run("Nonce/Agg", testNonceAggVectors)
	t.Run("Sign", testSignVectors)
	t.Run("PartialSig/Verify", testPartialSigVerifyVectors)
	t.Run("PartialSig/Agg", testPartialSigAggVectors)
}

func unpackTestVectors(t *testing.T, fn string, dst any) {
	f, err := os.Open(fn)
	require.NoError(t, err, "os.Open")
	defer f.Close()

	dec := json.NewDecoder(f)
	err = dec.Decode(dst)
	require.NoError(t, err, "dec.Decode")
}

type tvHeader struct {
	Sk        string   `json:"sk"`
	Pubkeys   []string `json:"pubkeys"`
	TweaksHex []string `json:"tweaks"`
	Secnonces []string `json:"secnonces"`
	Pnonces   []string `json:"pnonces"`
	Aggnonces []string `json:"aggnonces"`
	Msgs      []string `json:"msgs"`
	Psigs     []string `json:"psigs"`

	Valid []tvValidCase `json:"valid_test_cases"`
	Error []tvErrorCase `json:"error_test_cases"`

	SortedPubkeys []string `json:"sorted_pubkeys"` // KeySort
	MsgHex        string   `json:"msg"`            // PartialSigAgg

	// Cache deserialized values.
	//
	// Note: It is assumed that the test vectors are immutable.
	sk            *secec.PrivateKey
	pubKeys       []*secec.PublicKey
	pubKeysErrs   []error
	tweaks        [][]byte
	secNonces     []*SecretNonce
	secNoncesErrs []error
	pubNonces     []*PublicNonce
	pubNoncesErrs []error
	aggNonces     []*AggregatedPublicNonce
	aggNoncesErrs []error
	msgs          [][]byte
	pSigs         []*PartialSignature
	pSigsErrs     []error
}

func (hdr *tvHeader) SecKey(t *testing.T) *secec.PrivateKey {
	if hdr.sk != nil {
		return hdr.sk
	}

	sk, err := secec.NewPrivateKey(mustUnhex(hdr.Sk))
	require.NoError(t, err, "NewPrivateKey")
	hdr.sk = sk

	return sk
}

func (hdr *tvHeader) PubKeys() ([]*secec.PublicKey, []error) {
	if hdr.pubKeys != nil {
		return hdr.pubKeys, hdr.pubKeysErrs
	}

	l := len(hdr.Pubkeys)
	keys := make([]*secec.PublicKey, 0, l)
	errs := make([]error, 0, l)

	for _, x := range hdr.Pubkeys {
		pk, err := secec.NewPublicKey(mustUnhex(x))
		keys = append(keys, pk)
		errs = append(errs, err)
	}

	hdr.pubKeys = keys
	hdr.pubKeysErrs = errs

	return keys, errs
}

func (hdr *tvHeader) Tweaks() [][]byte {
	if hdr.tweaks != nil {
		return hdr.tweaks
	}

	tweaks := make([][]byte, 0, len(hdr.TweaksHex))

	for _, x := range hdr.TweaksHex {
		tweaks = append(tweaks, mustUnhex(x))
	}

	hdr.tweaks = tweaks

	return tweaks
}

func (hdr *tvHeader) SecNonces() ([]*SecretNonce, []error) {
	if hdr.secNonces != nil {
		return hdr.secNonces, hdr.secNoncesErrs
	}

	l := len(hdr.Secnonces)
	nonces := make([]*SecretNonce, 0, l)
	errs := make([]error, 0, l)

	for _, x := range hdr.Secnonces {
		n, err := NewSecretNonce(mustUnhex(x))
		nonces = append(nonces, n)
		errs = append(errs, err)
	}

	hdr.secNonces = nonces
	hdr.secNoncesErrs = errs

	return nonces, errs
}

func (hdr *tvHeader) PubNonces() ([]*PublicNonce, []error) {
	if hdr.pubNonces != nil {
		return hdr.pubNonces, hdr.pubNoncesErrs
	}

	l := len(hdr.Pnonces)
	nonces := make([]*PublicNonce, 0, l)
	errs := make([]error, 0, l)

	for _, x := range hdr.Pnonces {
		n, err := NewPublicNonce(mustUnhex(x))
		nonces = append(nonces, n)
		errs = append(errs, err)
	}

	hdr.pubNonces = nonces
	hdr.pubNoncesErrs = errs

	return nonces, errs
}

func (hdr *tvHeader) AggNonces() ([]*AggregatedPublicNonce, []error) {
	if hdr.aggNonces != nil {
		return hdr.aggNonces, hdr.aggNoncesErrs
	}

	l := len(hdr.Aggnonces)
	nonces := make([]*AggregatedPublicNonce, 0, l)
	errs := make([]error, 0, l)

	for _, x := range hdr.Aggnonces {
		n, err := NewAggregatedPublicNonce(mustUnhex(x))
		nonces = append(nonces, n)
		errs = append(errs, err)
	}

	hdr.aggNonces = nonces
	hdr.aggNoncesErrs = errs

	return nonces, errs
}

func (hdr *tvHeader) Messages() [][]byte {
	if hdr.msgs != nil {
		return hdr.msgs
	}

	msgs := make([][]byte, 0, len(hdr.Msgs))

	for _, x := range hdr.Msgs {
		msgs = append(msgs, mustUnhex(x))
	}

	hdr.msgs = msgs

	return msgs
}

func (hdr *tvHeader) PartialSigs() ([]*PartialSignature, []error) {
	if hdr.pSigs != nil {
		return hdr.pSigs, hdr.pSigsErrs
	}

	l := len(hdr.Psigs)
	psigs := make([]*PartialSignature, 0, l)
	errs := make([]error, 0, l)

	for _, x := range hdr.Psigs {
		sig, err := NewPartialSignature(mustUnhex(x))
		psigs = append(psigs, sig)
		errs = append(errs, err)
	}

	hdr.pSigs = psigs
	hdr.pSigsErrs = errs

	return psigs, errs
}

func (hdr *tvHeader) SortedPubKeys(t *testing.T) []*secec.PublicKey {
	keys := make([]*secec.PublicKey, 0, len(hdr.SortedPubkeys))

	for _, x := range hdr.SortedPubkeys {
		pk, err := secec.NewPublicKey(mustUnhex(x))
		require.NoError(t, err, "NewPublicKey")
		keys = append(keys, pk)
	}

	return keys
}

func (hdr *tvHeader) Msg() []byte {
	return mustUnhex(hdr.MsgHex)
}

func (hdr *tvHeader) PublicKeyAggregator(t *testing.T, indices []int) *PublicKeyAggregator {
	hdrPubKeys, errs := hdr.PubKeys()

	agg := NewPublicKeyAggregator()
	for _, idx := range indices {
		pk := hdrPubKeys[idx]
		require.NotNil(t, pk, "pubKey[%d]", idx)
		require.NoError(t, errs[idx])

		err := agg.Add(pk)
		require.NoError(t, err, "Add(pubKey[%d]", idx)
	}

	return agg
}

func (hdr *tvHeader) PublicNonceAggregator(t *testing.T, indices []int) *PublicNonceAggregator {
	hdrNonces, errs := hdr.PubNonces()

	agg := NewPublicNonceAggregator()
	for _, idx := range indices {
		nonce := hdrNonces[idx]
		require.NotNil(t, nonce, "nonce[%d]", idx)
		require.NoError(t, errs[idx])

		err := agg.Add(nonce)
		require.NoError(t, err, "Add(nonce[%d]", idx)
	}

	return agg
}

type tvValidCase struct {
	KeyIndices    []int  `json:"key_indices"`
	TweakIndices  []int  `json:"tweak_indices"`
	IsXOnly       []bool `json:"is_xonly"`
	NonceIndices  []int  `json:"nonce_indices"`
	PNonceIndices []int  `json:"pnonce_indices"`
	PSigIndices   []int  `json:"psig_indices"`
	AggNonceIndex int    `json:"aggnonce_index"`
	MsgIndex      int    `json:"msg_index"`
	SignerIndex   int    `json:"signer_index"`
	AggNonceHex   string `json:"aggnonce"`
	ExpectedHex   string `json:"expected"`
	Comment       string `json:"comment"`
}

func (ca *tvValidCase) Expected() []byte {
	return mustUnhex(ca.ExpectedHex)
}

func (ca *tvValidCase) AggNonce(t *testing.T) *AggregatedPublicNonce {
	n, err := NewAggregatedPublicNonce(mustUnhex(ca.AggNonceHex))
	require.NoError(t, err, "NewAggregatedPublicNonce")
	return n
}

type tvErrorCaseReason struct {
	Type    string `json:"type"`
	Signer  *int   `json:"signer"`
	Contrib string `json:"contrib"`
	Message string `json:"message"`
}

func (er *tvErrorCaseReason) Is(errType, contrib string) bool {
	return er.Type == errType && er.Contrib == contrib
}

type tvErrorCase struct {
	KeyIndices    []int             `json:"key_indices"`
	TweakIndices  []int             `json:"tweak_indices"`
	IsXOnly       []bool            `json:"is_xonly"`
	PNonceIndices []int             `json:"pnonce_indices"`
	PSigIndices   []int             `json:"psig_indices"`
	NonceIndices  []int             `json:"nonce_indices"`
	AggNonceIndex int               `json:"aggnonce_index"`
	SecNonceIndex int               `json:"secnonce_index"`
	MsgIndex      int               `json:"msg_index"`
	SignerIndex   int               `json:"signer_index"`
	Error         tvErrorCaseReason `json:"error"`
	Sig           string            `json:"sig"`
	Comment       string            `json:"comment"`
}
