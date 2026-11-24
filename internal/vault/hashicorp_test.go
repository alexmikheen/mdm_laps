// Copyright 2026 Aleksandr Mikheenko
// SPDX-License-Identifier: MIT

package vault

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/hashicorp/vault/api"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestHashiCorpClientIgnoresVaultSkipVerifyEnv(t *testing.T) {
	t.Setenv("VAULT_SKIP_VERIFY", "true")

	cfg, err := newHashiCorpConfig("https://127.0.0.1:8200")
	if err != nil {
		t.Fatalf("newHashiCorpConfig failed: %v", err)
	}
	if tlsCfg := cfg.TLSConfig(); tlsCfg == nil || tlsCfg.InsecureSkipVerify || tlsCfg.MinVersion < tls.VersionTLS12 {
		t.Fatalf("TLSConfig() = %+v, want InsecureSkipVerify=false and TLS 1.2+", tlsCfg)
	}
	transport, ok := cfg.HttpClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("transport TLSClientConfig.InsecureSkipVerify = true, want false")
	}
}

func TestHashiCorpSecretPathEscapesDeviceID(t *testing.T) {
	hc := &HashiCorpClient{path: "secret/data/laps"}

	cases := []struct {
		deviceID string
		want     string
	}{
		{"PF2ABCDE", "secret/data/laps/PF2ABCDE"},
		{"VMware-56 4d 12 ab", "secret/data/laps/VMware-56%204d%2012%20ab"},
		{"../other/secret", "secret/data/laps/..%2Fother%2Fsecret"},
		{"a?b#c%d", "secret/data/laps/a%3Fb%23c%25d"},
	}
	for _, tc := range cases {
		if got := hc.secretPath(tc.deviceID); got != tc.want {
			t.Fatalf("secretPath(%q) = %q, want %q", tc.deviceID, got, tc.want)
		}
	}
}

func TestHashiCorpClientUsesEscapedPathInHTTPRequests(t *testing.T) {
	var seenPaths []string
	cfg := api.DefaultConfig()
	cfg.Address = "https://vault.example.test"
	cfg.HttpClient = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			seenPaths = append(seenPaths, r.URL.Path)
			body := `{"data":{"data":{"login":"lapsadmin","password":"old"}}}`
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(body)),
				Request:    r,
			}, nil
		}),
	}
	client, err := api.NewClient(cfg)
	if err != nil {
		t.Fatalf("api.NewClient failed: %v", err)
	}
	hc := &HashiCorpClient{client: client, path: "secret/data/laps"}

	creds, err := hc.GetCredentials(context.Background(), "../other/secret", "unused", "lapsadmin")
	if err != nil {
		t.Fatalf("GetCredentials failed: %v", err)
	}
	if creds.ItemID != "secret/data/laps/..%2Fother%2Fsecret" {
		t.Fatalf("creds.ItemID = %q, want escaped path", creds.ItemID)
	}
	if len(seenPaths) != 1 || seenPaths[0] != "/v1/secret/data/laps/..%2Fother%2Fsecret" {
		t.Fatalf("HTTP request paths = %v, want [/v1/secret/data/laps/..%%2Fother%%2Fsecret]", seenPaths)
	}
}
