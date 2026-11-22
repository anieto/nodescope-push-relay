package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type apnsTestTransport func(*http.Request) (*http.Response, error)

func (transport apnsTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return transport(req)
}

func testAPNsKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testAPNsKeyFile(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signing.p8")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAPNsSenderRequiresP256AndHTTP2(t *testing.T) {
	prodKeyPath := testAPNsKeyFile(t, testAPNsKey(t, elliptic.P256()))
	if _, err := newAPNsSender("TEAMID1234", "PUSHKEY123", "com.btdev.nodescope", prodKeyPath, "development", ""); err != nil {
		t.Fatal(err)
	}
	badKeyPath := testAPNsKeyFile(t, testAPNsKey(t, elliptic.P384()))
	if _, err := newAPNsSender("TEAMID1234", "PUSHKEY123", "com.btdev.nodescope", badKeyPath, "development", ""); err == nil {
		t.Fatal("accepted a P-384 signing key")
	}
	client := newAPNsClient()
	transport := client.Transport.(*http.Transport)
	if !transport.Protocols.HTTP2() || transport.Protocols.HTTP1() ||
		transport.TLSClientConfig.MinVersion < 0x0303 {
		t.Fatal("APNs client does not enforce HTTP/2 and TLS 1.2 or later")
	}
}

func TestAPNsSandboxRequestAndJWT(t *testing.T) {
	key := testAPNsKey(t, elliptic.P256())
	now := time.Date(2026, 11, 18, 20, 0, 0, 0, time.UTC)
	job := Job{
		AnalyzerID: "an_test", Provider: "apns", Environment: "development",
		Token: strings.Repeat("ff", 32),
		Request: DeliveryRequest{
			EventID: "evt_test", SubscriptionID: "sub_test", Kind: "node.heard_again",
			NodePubkey: strings.Repeat("a", 64), OccurredAt: now, ExpiresAt: now.Add(time.Hour),
		},
	}
	var tokens []string
	client := &http.Client{Transport: apnsTestTransport(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost || req.URL.Host != "api.sandbox.push.apple.com" ||
			req.URL.Path != "/3/device/"+job.Token || req.URL.Scheme != "https" {
			t.Fatal("wrong APNs sandbox request")
		}
		for header, expected := range map[string]string{
			"apns-topic": "com.btdev.nodescope", "apns-push-type": "alert", "apns-priority": "10",
			"apns-expiration": strconv.FormatInt(job.Request.ExpiresAt.Unix(), 10), "content-type": "application/json",
		} {
			if req.Header.Get(header) != expected {
				t.Fatalf("wrong %s: got %q, want %q", header, req.Header.Get(header), expected)
			}
		}
		tokens = append(tokens, strings.TrimPrefix(req.Header.Get("Authorization"), "bearer "))
		var payload struct {
			APS struct {
				Alert struct {
					Title string
					Body  string
				}
			}
			Version        string
			AnalyzerID     string `json:"analyzer_id"`
			SubscriptionID string `json:"subscription_id"`
			EventID        string `json:"event_id"`
			Kind           string
			NodePubkey     string `json:"node_pubkey"`
		}
		if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		if payload.APS.Alert.Title == "" || payload.APS.Alert.Body == "" || payload.Version != "1" ||
			payload.AnalyzerID != job.AnalyzerID || payload.SubscriptionID != job.Request.SubscriptionID ||
			payload.EventID != job.Request.EventID || payload.Kind != job.Request.Kind ||
			payload.NodePubkey != job.Request.NodePubkey || strings.Contains(payload.APS.Alert.Body, payload.NodePubkey) {
			t.Fatal("expected generic alert and versioned routing metadata")
		}
		return &http.Response{StatusCode: 200, ProtoMajor: 2, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	sender := &apnsSender{environment: "development",
		teamID: "TEAMID1234", keyID: "PUSHKEY123", topic: "com.btdev.nodescope", key: key,
		client: client, now: func() time.Time { return now },
	}
	if res := sender.send(context.Background(), job); res.Status != sendAccepted {
		t.Fatalf("sandbox send: %v", res)
	}
	firstIssued := now
	now = now.Add(25 * time.Minute)
	if res := sender.send(context.Background(), job); res.Status != sendAccepted {
		t.Fatalf("second sandbox send: %v", res)
	}
	now = now.Add(26 * time.Minute)
	if res := sender.send(context.Background(), job); res.Status != sendAccepted {
		t.Fatalf("third sandbox send: %v", res)
	}
	if len(tokens) != 3 || tokens[0] != tokens[1] || tokens[1] == tokens[2] {
		t.Fatal("provider JWT was refreshed too soon or failed to refresh after 50 minutes")
	}
	verifyAPNsJWT(t, key, tokens[0], firstIssued)
	verifyAPNsJWT(t, key, tokens[2], now)
	job.Environment = "production"
	if res := sender.send(context.Background(), job); res.Status != sendRejected || len(tokens) != 3 {
		t.Fatal("a production token reached sandbox")
	}
}

func verifyAPNsJWT(t *testing.T, key *ecdsa.PrivateKey, token string, now time.Time) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatal("invalid JWT segments")
	}
	decode := func(index int) []byte {
		data, err := base64.RawURLEncoding.DecodeString(parts[index])
		if err != nil {
			t.Fatal("invalid JWT base64url")
		}
		return data
	}
	var header struct{ Alg, Kid string }
	var claims struct {
		Iss string
		Iat int64
	}
	if json.Unmarshal(decode(0), &header) != nil || json.Unmarshal(decode(1), &claims) != nil ||
		header.Alg != "ES256" || header.Kid != "PUSHKEY123" || claims.Iss != "TEAMID1234" || claims.Iat != now.Unix() {
		t.Fatal("invalid provider JWT header or claims")
	}
	signature := decode(2)
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if len(signature) != 64 || !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		t.Fatal("bad ES256 signature")
	}
}

func TestAPNsProviderResponseClassification(t *testing.T) {
	cases := []struct {
		code   int
		reason string
		retry  string
		want   SendResult
	}{
		{200, "", "", SendResult{Status: sendAccepted}},
		{410, "Unregistered", "", SendResult{Status: sendInvalidToken}},
		{410, "ExpiredToken", "", SendResult{Status: sendInvalidToken}},
		{410, "", "", SendResult{Status: sendRejected}},
		{400, "BadDeviceToken", "", SendResult{Status: sendRejected}},
		{400, "DeviceTokenNotForTopic", "", SendResult{Status: sendRejected}},
		{401, "", "", SendResult{Status: sendRetry, RetryAfter: time.Minute}},
		{403, "ExpiredProviderToken", "120", SendResult{Status: sendRetry, RetryAfter: 2 * time.Minute}},
		{403, "BadEnvironmentKeyIdInToken", "", SendResult{Status: sendRetry, RetryAfter: time.Minute}},
		{403, "Forbidden", "", SendResult{Status: sendRejected}},
		{429, "TooManyRequests", "165", SendResult{Status: sendRetry, RetryAfter: 165 * time.Second}},
		{429, "TooManyProviderTokenUpdates", "", SendResult{Status: sendRetry, RetryAfter: 20 * time.Minute}},
		{503, "ServiceUnavailable", "", SendResult{Status: sendRetry, RetryAfter: 15 * time.Minute}},
	}
	for _, tc := range cases {
		response := &http.Response{StatusCode: tc.code, Header: make(http.Header), ProtoMajor: 2}
		response.Header.Set("Retry-After", tc.retry)
		got := classifyAPNsResponse(response, tc.reason, time.Now())
		if tc.want != got {
			t.Errorf("response %d %s: got %+v, want %+v", tc.code, tc.reason, got, tc.want)
		}
	}
}

func TestAPNsProductionUsesProductionEndpoint(t *testing.T) {
	now := time.Date(2026, 11, 18, 20, 0, 0, 0, time.UTC)
	sends := 0
	sender := &apnsSender{
		environment: "production", teamID: "TEAMID1234", keyID: "PUSHKEY123", topic: "com.btdev.nodescope",
		key: testAPNsKey(t, elliptic.P256()), now: func() time.Time { return now },
		client: &http.Client{Transport: apnsTestTransport(func(r *http.Request) (*http.Response, error) {
			sends++
			if r.URL.Scheme != "https" || r.URL.Host != "api.push.apple.com" {
				t.Fatalf("unexpected APNs production endpoint: %s", r.URL.Host)
			}
			return &http.Response{StatusCode: http.StatusOK, ProtoMajor: 2, Body: http.NoBody}, nil
		})},
	}
	job := Job{Provider: "apns", Environment: "production", Token: strings.Repeat("ff", 32),
		Request: DeliveryRequest{ExpiresAt: now.Add(time.Hour)}}
	if result := sender.send(context.Background(), job); result.Status != sendAccepted {
		t.Fatalf("production send: %+v", result)
	}
	job.Environment = "development"
	if result := sender.send(context.Background(), job); result.Status != sendRejected || sends != 1 {
		t.Fatalf("sandbox token on production sender: %+v, requests=%d", result, sends)
	}
}
