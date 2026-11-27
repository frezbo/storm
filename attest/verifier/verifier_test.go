package verifier_test

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/stretchr/testify/require"

	"github.com/frezbo/storm/attest/verifier"
	"github.com/frezbo/storm/attest/wire"
)

type simChannel struct{ *simulator.Simulator }

func (simChannel) MeasurementLog() ([]byte, error) { return nil, nil }

type machine struct {
	tpm *attest.TPM
	ak  *attest.AK
	ek  []byte
}

func newMachine(t *testing.T) machine {
	t.Helper()

	sim, err := simulator.Get()
	require.NoError(t, err)

	tpm, err := attest.OpenTPM(&attest.OpenConfig{CommandChannel: simChannel{sim}})
	require.NoError(t, err)
	t.Cleanup(func() { tpm.Close() })

	eks, err := tpm.EKs()
	require.NoError(t, err)
	require.NotEmpty(t, eks)

	ek, err := x509.MarshalPKIXPublicKey(eks[0].Public)
	require.NoError(t, err)

	ak, err := tpm.NewAK(nil)
	require.NoError(t, err)
	t.Cleanup(func() { ak.Close(tpm) })

	return machine{tpm: tpm, ak: ak, ek: ek}
}

// enrolled returns the policy matching m: its EK hash and current PCR 7.
func (m machine) enrolled(t *testing.T) verifier.Policy {
	t.Helper()

	sum := sha256.Sum256(m.ek)

	pcrs, err := m.tpm.PCRs(attest.HashSHA256)
	require.NoError(t, err)

	for _, p := range pcrs {
		if p.Index == 7 {
			return verifier.Policy{EKSHA256: sum[:], PCR7: p.Digest}
		}
	}

	t.Fatal("no PCR 7 in the SHA-256 bank")

	return verifier.Policy{}
}

// answer builds the attester's reply to ch the way cmd/attester does, with the key the auth
// key is sealed to.
func (m machine) answer(t *testing.T, ch wire.ChallengeResponse) (wire.AttestRequest, *ecdh.PrivateKey) {
	t.Helper()

	secret, err := m.ak.ActivateCredential(m.tpm, ch.Credential)
	require.NoError(t, err)

	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)

	quote, err := m.ak.Quote(m.tpm, wire.QuoteNonce(ch.Nonce, recipient.PublicKey().Bytes()), attest.HashSHA256)
	require.NoError(t, err)

	pcrs, err := m.tpm.PCRs(attest.HashSHA256)
	require.NoError(t, err)

	return wire.AttestRequest{
		ID:        ch.ID,
		Secret:    secret,
		Recipient: recipient.PublicKey().Bytes(),
		Quote:     *quote,
		PCRs:      pcrs,
	}, recipient
}

func (m machine) request() wire.ChallengeRequest {
	return wire.ChallengeRequest{EK: m.ek, AK: m.ak.AttestationParameters()}
}

type counter struct{ calls int }

func (c *counter) mint(context.Context) (string, error) {
	c.calls++

	return "tskey-auth-test", nil
}

func TestAttest(t *testing.T) {
	m := newMachine(t)
	policy := m.enrolled(t)

	t.Run("enrolled machine gets a key", func(t *testing.T) {
		var c counter
		v := verifier.New(policy, c.mint)

		ch, err := v.Challenge(m.request())
		require.NoError(t, err)

		req, recipient := m.answer(t, ch)

		res, err := v.Attest(t.Context(), req)
		require.NoError(t, err)
		require.NotContains(t, string(res.SealedAuthKey), "tskey-auth-test", "the auth key must not cross the LAN in the clear")

		key, err := wire.Open(recipient, res.SealedAuthKey)
		require.NoError(t, err)
		require.Equal(t, "tskey-auth-test", string(key))
		require.Equal(t, 1, c.calls)
	})

	t.Run("a relay cannot substitute its own recipient key", func(t *testing.T) {
		var c counter
		v := verifier.New(policy, c.mint)

		ch, err := v.Challenge(m.request())
		require.NoError(t, err)

		req, _ := m.answer(t, ch)

		attacker, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)

		req.Recipient = attacker.PublicKey().Bytes()

		_, err = v.Attest(t.Context(), req)
		require.ErrorIs(t, err, verifier.ErrDenied)
		require.Zero(t, c.calls)
	})

	t.Run("unenrolled EK is refused before any challenge", func(t *testing.T) {
		other := policy
		other.EKSHA256 = make([]byte, 32)

		_, err := verifier.New(other, (&counter{}).mint).Challenge(m.request())
		require.ErrorIs(t, err, verifier.ErrDenied)
	})

	t.Run("PCR 7 drift is refused and mints nothing", func(t *testing.T) {
		other := policy
		other.PCR7 = make([]byte, 32)
		other.PCR7[0] = 1

		var c counter
		v := verifier.New(other, c.mint)

		ch, err := v.Challenge(m.request())
		require.NoError(t, err)

		req, _ := m.answer(t, ch)

		_, err = v.Attest(t.Context(), req)
		require.ErrorIs(t, err, verifier.ErrDenied)
		require.Zero(t, c.calls)
	})

	t.Run("a duplicated PCR cannot smuggle the enrolled value past the quote", func(t *testing.T) {
		// The quote digest is checked against the last entry per index, but every entry with
		// that index is marked verified, so a forged first entry would otherwise be trusted.
		drifted := policy
		drifted.PCR7 = make([]byte, 32)
		drifted.PCR7[0] = 1

		var c counter
		v := verifier.New(drifted, c.mint)

		ch, err := v.Challenge(m.request())
		require.NoError(t, err)

		req, _ := m.answer(t, ch)
		req.PCRs = append([]attest.PCR{{Index: 7, Digest: drifted.PCR7, DigestAlg: crypto.SHA256}}, req.PCRs...)

		_, err = v.Attest(t.Context(), req)
		require.ErrorIs(t, err, verifier.ErrDenied)
		require.Zero(t, c.calls)
	})

	t.Run("secret not activated by the TPM is refused", func(t *testing.T) {
		v := verifier.New(policy, (&counter{}).mint)

		ch, err := v.Challenge(m.request())
		require.NoError(t, err)

		req, _ := m.answer(t, ch)
		req.Secret = make([]byte, len(req.Secret))

		_, err = v.Attest(t.Context(), req)
		require.ErrorIs(t, err, verifier.ErrDenied)
	})

	t.Run("quote over another nonce is refused", func(t *testing.T) {
		v := verifier.New(policy, (&counter{}).mint)

		ch, err := v.Challenge(m.request())
		require.NoError(t, err)

		stale := ch
		stale.Nonce = make([]byte, len(ch.Nonce))

		req, _ := m.answer(t, stale)
		req.Secret, err = m.ak.ActivateCredential(m.tpm, ch.Credential)
		require.NoError(t, err)

		_, err = v.Attest(t.Context(), req)
		require.ErrorIs(t, err, verifier.ErrDenied)
	})

	t.Run("a session cannot be replayed", func(t *testing.T) {
		var c counter
		v := verifier.New(policy, c.mint)

		ch, err := v.Challenge(m.request())
		require.NoError(t, err)

		req, _ := m.answer(t, ch)

		_, err = v.Attest(t.Context(), req)
		require.NoError(t, err)

		_, err = v.Attest(t.Context(), req)
		require.ErrorIs(t, err, verifier.ErrDenied)
		require.Equal(t, 1, c.calls)
	})
}

func TestAttestSessionExpires(t *testing.T) {
	m := newMachine(t)
	policy := m.enrolled(t)

	synctest.Test(t, func(t *testing.T) {
		v := verifier.New(policy, func(context.Context) (string, error) {
			return "", errors.New("must not mint")
		})

		ch, err := v.Challenge(m.request())
		require.NoError(t, err)

		req, _ := m.answer(t, ch)

		time.Sleep(verifier.SessionTTL + time.Second)

		_, err = v.Attest(t.Context(), req)
		require.ErrorIs(t, err, verifier.ErrDenied)
	})
}
