// Command attester proves Storm's TPM identity and Secure Boot state to the verifier and writes
// the one-off Tailscale auth key it returns, for the tailscale extension to read via
// TS_AUTHKEY=file:<path>.
//
// It runs for as long as the machine does and attests whenever tailscaled needs a login: Omni
// 1.13 rejects ContainerConfig lifecycle settings, so the container restarts after every exit.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/google/go-attestation/attest"

	"github.com/frezbo/storm/attest/wire"
)

func main() {
	verifier := flag.String("verifier", "", "verifier base URL")
	out := flag.String("out", "/var/lib/tailscale/authkey", "auth key output path")
	socket := flag.String("socket", "/var/run/tailscale/tailscaled.sock", "tailscaled LocalAPI socket")
	printPolicy := flag.Bool("print-policy", false, "print the EK hash and PCR 7 for enrollment, then exit")
	interval := flag.Duration("interval", 30*time.Second, "how often to check tailscaled")
	flag.Parse()

	if *printPolicy {
		if err := withTPM(enroll); err != nil {
			log.Fatal(err)
		}

		return
	}

	if *verifier == "" {
		log.Fatal("-verifier is required")
	}

	last := ""

	for {
		state, err := check(*verifier, *out, *socket)
		if err != nil {
			log.Print(err)
		} else if state != last {
			log.Printf("tailscale backend is %s", state)
		}

		last = state

		time.Sleep(*interval)
	}
}

// keyTTL matches the expiry the verifier gives minted keys.
const keyTTL = 10 * time.Minute

// check attests when tailscaled needs a login and no unexpired key is waiting for it, then logs
// tailscaled in with that key. tailscaled.state is written before the first login, so
// tailscaled's own status is the signal.
func check(verifier, out, socket string) (string, error) {
	lc := localClient(socket)

	state, needsLogin, err := backendState(lc)
	if err != nil {
		return "", fmt.Errorf("tailscaled not ready: %w", err)
	}

	if !needsLogin {
		return state, nil
	}

	if fi, err := os.Stat(out); err == nil && time.Since(fi.ModTime()) < keyTTL {
		return state, nil
	}

	var key string

	if err := withTPM(func(tpm *attest.TPM) error {
		key, err = run(tpm, verifier)

		return err
	}); err != nil {
		return state, err
	}

	// Rename so the extension never reads a partial key.
	tmp := out + ".tmp"
	if err := os.WriteFile(tmp, []byte(key), 0o600); err != nil {
		return state, err
	}

	if err := os.Rename(tmp, out); err != nil {
		return state, err
	}

	log.Printf("auth key written to %s", filepath.Clean(out))

	// The tailscale extension reads the file only when it starts. A node that lost its login
	// while running (removed from the tailnet) needs the key handed to tailscaled directly.
	if err := login(lc, key); err != nil {
		return state, fmt.Errorf("log in: %w", err)
	}

	log.Print("tailscaled login started with the minted key")

	return state, nil
}

func withTPM(f func(*attest.TPM) error) error {
	tpm, err := attest.OpenTPM(&attest.OpenConfig{})
	if err != nil {
		return fmt.Errorf("open TPM: %w", err)
	}
	defer tpm.Close()

	return f(tpm)
}

func localClient(socket string) *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}
}

// backendState returns tailscaled's ipn.State name and whether it needs a login. A node removed
// from the tailnet keeps reporting Running with a pending AuthURL, so NeedsLogin alone misses it.
func backendState(lc *http.Client) (string, bool, error) {
	resp, err := lc.Get("http://local-tailscaled.sock/localapi/v0/status?peers=false")
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", false, fmt.Errorf("status: %s", resp.Status)
	}

	var status struct {
		BackendState string
		AuthURL      string
	}

	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return "", false, err
	}

	if status.BackendState == "" || status.BackendState == "NoState" {
		return "", false, errors.New("backend not started")
	}

	if status.AuthURL != "" {
		return status.BackendState + " (login pending)", true, nil
	}

	return status.BackendState, status.BackendState == "NeedsLogin", nil
}

// login starts tailscaled's login with key, as `tailscale up --auth-key` does.
func login(lc *http.Client, key string) error {
	body, err := json.Marshal(map[string]string{"AuthKey": key})
	if err != nil {
		return err
	}

	resp, err := lc.Post("http://local-tailscaled.sock/localapi/v0/start", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))

		return fmt.Errorf("%s: %s", resp.Status, bytes.TrimSpace(msg))
	}

	return nil
}

func ekDER(tpm *attest.TPM) ([]byte, error) {
	eks, err := tpm.EKs()
	if err != nil {
		return nil, fmt.Errorf("read EK: %w", err)
	}

	if len(eks) == 0 {
		return nil, errors.New("no EK")
	}

	return x509.MarshalPKIXPublicKey(eks[0].Public)
}

func enroll(tpm *attest.TPM) error {
	der, err := ekDER(tpm)
	if err != nil {
		return err
	}

	pcrs, err := tpm.PCRs(attest.HashSHA256)
	if err != nil {
		return fmt.Errorf("read PCRs: %w", err)
	}

	sum := sha256.Sum256(der)
	fmt.Printf("EK_SHA256=%s\n", hex.EncodeToString(sum[:]))

	for _, p := range pcrs {
		if p.Index == 7 {
			fmt.Printf("PCR7=%s\n", hex.EncodeToString(p.Digest))
		}
	}

	return nil
}

func run(tpm *attest.TPM, verifier string) (string, error) {
	der, err := ekDER(tpm)
	if err != nil {
		return "", err
	}

	ak, err := tpm.NewAK(nil)
	if err != nil {
		return "", fmt.Errorf("create AK: %w", err)
	}
	defer ak.Close(tpm)

	var ch wire.ChallengeResponse
	if err := post(verifier+"/v1/challenge", wire.ChallengeRequest{EK: der, AK: ak.AttestationParameters()}, &ch); err != nil {
		return "", err
	}

	secret, err := ak.ActivateCredential(tpm, ch.Credential)
	if err != nil {
		return "", fmt.Errorf("activate credential: %w", err)
	}

	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}

	quote, err := ak.Quote(tpm, wire.QuoteNonce(ch.Nonce, recipient.PublicKey().Bytes()), attest.HashSHA256)
	if err != nil {
		return "", fmt.Errorf("quote: %w", err)
	}

	pcrs, err := tpm.PCRs(attest.HashSHA256)
	if err != nil {
		return "", fmt.Errorf("read PCRs: %w", err)
	}

	var res wire.AttestResponse
	if err := post(verifier+"/v1/attest", wire.AttestRequest{
		ID:        ch.ID,
		Secret:    secret,
		Recipient: recipient.PublicKey().Bytes(),
		Quote:     *quote,
		PCRs:      pcrs,
	}, &res); err != nil {
		return "", err
	}

	key, err := wire.Open(recipient, res.SealedAuthKey)
	if err != nil {
		return "", fmt.Errorf("open auth key: %w", err)
	}

	return string(key), nil
}

func post(url string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))

		return fmt.Errorf("%s: %s: %s", url, resp.Status, bytes.TrimSpace(msg))
	}

	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}
