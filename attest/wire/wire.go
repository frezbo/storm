// Package wire defines the JSON messages between the Storm attester and the Fly verifier.
//
// The LAN leg to Fly's private network is plain HTTP, so the auth key is sealed to an X25519
// key that the attester generates per join. QuoteNonce binds that key into the TPM quote:
// whoever relays the exchange cannot substitute their own key without breaking the quote.
package wire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/google/go-attestation/attest"
)

// ChallengeRequest opens an attestation: the EK identifies the TPM, the AK will sign the quote.
type ChallengeRequest struct {
	EK []byte                       `json:"ek"` // PKIX DER
	AK attest.AttestationParameters `json:"ak"`
}

// ChallengeResponse carries the credential only the EK's TPM can activate, and the quote nonce.
type ChallengeResponse struct {
	ID         string                     `json:"id"`
	Credential attest.EncryptedCredential `json:"credential"`
	Nonce      []byte                     `json:"nonce"`
}

// AttestRequest proves AK residency (Secret) and the platform state (Quote over PCRs, with
// QuoteNonce(Nonce, Recipient) as the quote's nonce).
type AttestRequest struct {
	ID        string       `json:"id"`
	Secret    []byte       `json:"secret"`
	Recipient []byte       `json:"recipient"` // X25519 public key
	Quote     attest.Quote `json:"quote"`
	PCRs      []attest.PCR `json:"pcrs"`
}

// AttestResponse returns a one-off Tailscale auth key sealed to the request's Recipient.
type AttestResponse struct {
	SealedAuthKey []byte `json:"sealedAuthKey"`
}

// QuoteNonce is the nonce the attester quotes over: the verifier's nonce bound to the recipient key.
func QuoteNonce(nonce, recipient []byte) []byte {
	h := sha256.New()
	h.Write(nonce)
	h.Write(recipient)

	return h.Sum(nil)
}

const sealInfo = "storm-attest auth key"

// Seal encrypts plaintext to the X25519 public key recipient.
// The output is the ephemeral public key, the GCM nonce, then the ciphertext.
func Seal(recipient, plaintext []byte) ([]byte, error) {
	pub, err := ecdh.X25519().NewPublicKey(recipient)
	if err != nil {
		return nil, err
	}

	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	aead, err := sealAEAD(eph, pub, eph.PublicKey().Bytes(), recipient)
	if err != nil {
		return nil, err
	}

	out := append(eph.PublicKey().Bytes(), make([]byte, aead.NonceSize())...)
	rand.Read(out[len(out)-aead.NonceSize():])

	return aead.Seal(out, out[len(out)-aead.NonceSize():], plaintext, nil), nil
}

// Open decrypts the output of Seal with the recipient's private key.
func Open(priv *ecdh.PrivateKey, sealed []byte) ([]byte, error) {
	const pubLen = 32

	if len(sealed) < pubLen {
		return nil, errors.New("sealed data too short")
	}

	eph, err := ecdh.X25519().NewPublicKey(sealed[:pubLen])
	if err != nil {
		return nil, err
	}

	aead, err := sealAEAD(priv, eph, sealed[:pubLen], priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}

	rest := sealed[pubLen:]
	if len(rest) < aead.NonceSize() {
		return nil, errors.New("sealed data too short")
	}

	return aead.Open(nil, rest[:aead.NonceSize()], rest[aead.NonceSize():], nil)
}

func sealAEAD(priv *ecdh.PrivateKey, peer *ecdh.PublicKey, ephPub, recipient []byte) (cipher.AEAD, error) {
	shared, err := priv.ECDH(peer)
	if err != nil {
		return nil, err
	}

	key, err := hkdf.Key(sha256.New, shared, append(append([]byte{}, ephPub...), recipient...), sealInfo, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}
