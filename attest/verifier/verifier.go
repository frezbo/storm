// Package verifier checks a TPM attestation from Storm and, when it matches the enrolled
// policy, mints a one-off Tailscale auth key.
//
// A join takes two requests. Challenge checks the EK against the enrolled pin and returns a
// credential that only that TPM can activate for the presented AK, plus a nonce. Attest checks
// the activated secret, the AK's quote over that nonce and PCR 7, then mints. Sessions are
// single use and expire after SessionTTL.
package verifier

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/google/go-attestation/attest"

	"github.com/frezbo/storm/attest/wire"
)

// SessionTTL bounds the time between Challenge and Attest.
const SessionTTL = time.Minute

// ErrDenied is returned for any attestation that does not match the policy.
var ErrDenied = errors.New("attestation denied")

// Policy is the enrolled identity and boot state of the machine.
type Policy struct {
	EKSHA256 []byte // SHA-256 of the PKIX DER EK public key
	PCR7     []byte // SHA-256 bank value: Secure Boot policy and keys
}

// Minter returns a one-off auth key for an attested machine.
type Minter func(ctx context.Context) (string, error)

// Server holds the policy and the open sessions.
type Server struct {
	mint     Minter
	sessions map[string]session
	policy   Policy
	mu       sync.Mutex
}

type session struct {
	expires  time.Time
	secret   []byte
	nonce    []byte
	akPublic []byte
}

// New returns a verifier for policy that calls mint for each successful attestation.
func New(policy Policy, mint Minter) *Server {
	return &Server{
		policy:   policy,
		mint:     mint,
		sessions: map[string]session{},
	}
}

// Challenge starts an attestation for the TPM holding req.EK.
func (s *Server) Challenge(req wire.ChallengeRequest) (wire.ChallengeResponse, error) {
	sum := sha256.Sum256(req.EK)
	if subtle.ConstantTimeCompare(sum[:], s.policy.EKSHA256) != 1 {
		return wire.ChallengeResponse{}, fmt.Errorf("%w: EK %s is not enrolled", ErrDenied, hex.EncodeToString(sum[:]))
	}

	ek, err := x509.ParsePKIXPublicKey(req.EK)
	if err != nil {
		return wire.ChallengeResponse{}, fmt.Errorf("%w: EK: %v", ErrDenied, err)
	}

	params := attest.ActivationParameters{EK: ek, AK: req.AK}

	secret, credential, err := params.Generate()
	if err != nil {
		return wire.ChallengeResponse{}, fmt.Errorf("%w: AK: %v", ErrDenied, err)
	}

	id, nonce := rand.Text(), make([]byte, 32)
	rand.Read(nonce)

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for k, v := range s.sessions {
		if now.After(v.expires) {
			delete(s.sessions, k)
		}
	}

	s.sessions[id] = session{
		expires:  now.Add(SessionTTL),
		secret:   secret,
		nonce:    nonce,
		akPublic: req.AK.Public,
	}

	return wire.ChallengeResponse{ID: id, Credential: *credential, Nonce: nonce}, nil
}

// Attest completes the session in req and mints an auth key when the evidence matches.
func (s *Server) Attest(ctx context.Context, req wire.AttestRequest) (wire.AttestResponse, error) {
	s.mu.Lock()
	sess, ok := s.sessions[req.ID]
	delete(s.sessions, req.ID)
	s.mu.Unlock()

	if !ok || time.Now().After(sess.expires) {
		return wire.AttestResponse{}, fmt.Errorf("%w: unknown or expired session", ErrDenied)
	}

	if subtle.ConstantTimeCompare(req.Secret, sess.secret) != 1 {
		return wire.AttestResponse{}, fmt.Errorf("%w: credential not activated by the enrolled TPM", ErrDenied)
	}

	if _, err := ecdh.X25519().NewPublicKey(req.Recipient); err != nil {
		return wire.AttestResponse{}, fmt.Errorf("%w: recipient key: %v", ErrDenied, err)
	}

	// go-attestation checks the quote digest against the last entry per PCR but marks every
	// entry with that index verified, so a duplicate could carry a forged value past Verify.
	if err := uniquePCRs(req.PCRs); err != nil {
		return wire.AttestResponse{}, fmt.Errorf("%w: %v", ErrDenied, err)
	}

	ak, err := attest.ParseAKPublic(sess.akPublic)
	if err != nil {
		return wire.AttestResponse{}, fmt.Errorf("%w: AK: %v", ErrDenied, err)
	}

	// Verify marks the PCRs the quote covers; only those are trusted below. The quoted nonce
	// binds req.Recipient, so the sealed key reaches only the quoting machine.
	if err := ak.Verify(req.Quote, req.PCRs, wire.QuoteNonce(sess.nonce, req.Recipient)); err != nil {
		return wire.AttestResponse{}, fmt.Errorf("%w: quote: %v", ErrDenied, err)
	}

	if !pcrMatches(req.PCRs, 7, s.policy.PCR7) {
		return wire.AttestResponse{}, fmt.Errorf("%w: PCR 7 does not match the policy", ErrDenied)
	}

	key, err := s.mint(ctx)
	if err != nil {
		return wire.AttestResponse{}, fmt.Errorf("mint auth key: %w", err)
	}

	sealed, err := wire.Seal(req.Recipient, []byte(key))
	if err != nil {
		return wire.AttestResponse{}, fmt.Errorf("seal auth key: %w", err)
	}

	return wire.AttestResponse{SealedAuthKey: sealed}, nil
}

func uniquePCRs(pcrs []attest.PCR) error {
	type key struct {
		index int
		alg   crypto.Hash
	}

	seen := make(map[key]struct{}, len(pcrs))

	for _, p := range pcrs {
		k := key{p.Index, p.DigestAlg}
		if _, dup := seen[k]; dup {
			return fmt.Errorf("PCR %d (%s) listed twice", p.Index, p.DigestAlg)
		}

		seen[k] = struct{}{}
	}

	return nil
}

func pcrMatches(pcrs []attest.PCR, index int, want []byte) bool {
	for _, p := range pcrs {
		if p.Index == index && p.DigestAlg == crypto.SHA256 && p.QuoteVerified() {
			return bytes.Equal(p.Digest, want)
		}
	}

	return false
}

// Handler serves POST /v1/challenge and POST /v1/attest.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /v1/challenge", func(w http.ResponseWriter, r *http.Request) {
		var req wire.ChallengeRequest
		if !decode(w, r, &req) {
			return
		}

		res, err := s.Challenge(req)
		reply(w, res, err)
	})

	mux.HandleFunc("POST /v1/attest", func(w http.ResponseWriter, r *http.Request) {
		var req wire.AttestRequest
		if !decode(w, r, &req) {
			return
		}

		res, err := s.Attest(r.Context(), req)
		reply(w, res, err)
	})

	return mux
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)

		return false
	}

	return true
}

func reply(w http.ResponseWriter, v any, err error) {
	switch {
	case errors.Is(err, ErrDenied):
		log.Print(err)
		http.Error(w, "denied", http.StatusForbidden)
	case err != nil:
		log.Print(err)
		http.Error(w, "upstream error", http.StatusBadGateway)
	default:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
}
