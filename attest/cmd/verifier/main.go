// Command verifier runs on Fly. It attests Storm (package verifier) and mints one-off Tailscale
// auth keys using the Machine's Fly OIDC token, exchanged through Tailscale workload identity
// federation, so it holds no Tailscale secret.
//
// Configuration (none of it secret):
//
//	EK_SHA256     enrolled EK hash, from `attester -print-policy`
//	PCR7          enrolled PCR 7 value, from `attester -print-policy`
//	TS_CLIENT_ID  trust credential client ID
//	TS_AUDIENCE   trust credential audience
//	TS_TAG        tag for the minted key, e.g. tag:storm
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/frezbo/storm/attest/verifier"
)

func main() {
	policy := verifier.Policy{
		EKSHA256: mustHex("EK_SHA256"),
		PCR7:     mustHex("PCR7"),
	}

	m := minter{
		clientID: mustEnv("TS_CLIENT_ID"),
		audience: mustEnv("TS_AUDIENCE"),
		tag:      mustEnv("TS_TAG"),
		http:     &http.Client{Timeout: 30 * time.Second},
		fly: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", "/.fly/api")
				},
			},
		},
	}

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           verifier.New(policy, m.mint).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Fatal(srv.ListenAndServe())
}

func mustEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("%s is required", name)
	}

	return v
}

func mustHex(name string) []byte {
	b, err := hex.DecodeString(mustEnv(name))
	if err != nil || len(b) != 32 {
		log.Fatalf("%s must be 32 hex-encoded bytes", name)
	}

	return b
}

type minter struct {
	http     *http.Client
	fly      *http.Client
	clientID string
	audience string
	tag      string
}

func (m minter) mint(ctx context.Context) (string, error) {
	idToken, err := m.flyToken(ctx)
	if err != nil {
		return "", fmt.Errorf("fly OIDC token: %w", err)
	}

	var exchanged struct {
		AccessToken string `json:"access_token"`
	}

	form := url.Values{"client_id": {m.clientID}, "jwt": {idToken}}
	if err := m.do(ctx, http.MethodPost, "https://api.tailscale.com/api/v2/oauth/token-exchange",
		"application/x-www-form-urlencoded", form.Encode(), "", &exchanged); err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}

	body, err := json.Marshal(map[string]any{
		"description":   "storm-attest",
		"expirySeconds": 600,
		"capabilities": map[string]any{
			"devices": map[string]any{
				"create": map[string]any{
					"reusable":      false,
					"ephemeral":     false,
					"preauthorized": true,
					"tags":          []string{m.tag},
				},
			},
		},
	})
	if err != nil {
		return "", err
	}

	var key struct {
		Key string `json:"key"`
	}

	if err := m.do(ctx, http.MethodPost, "https://api.tailscale.com/api/v2/tailnet/-/keys",
		"application/json", string(body), exchanged.AccessToken, &key); err != nil {
		return "", fmt.Errorf("create auth key: %w", err)
	}

	return key.Key, nil
}

// flyToken asks the local Machines API for an OIDC token with the Tailscale audience.
func (m minter) flyToken(ctx context.Context) (string, error) {
	body, err := json.Marshal(map[string]string{"aud": m.audience})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://localhost/v1/tokens/oidc", strings.NewReader(string(body)))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := m.fly.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s", resp.Status)
	}

	return strings.Trim(strings.TrimSpace(string(raw)), `"`), nil
}

func (m minter) do(ctx context.Context, method, target, contentType, body, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", contentType)

	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}

	resp, err := m.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Tailscale error bodies carry no credentials; include them for diagnosis.
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))

		return fmt.Errorf("%s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}

	return json.NewDecoder(resp.Body).Decode(out)
}
