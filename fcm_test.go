package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fcmTestTransport func(*http.Request) (*http.Response, error)

func (f fcmTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func fcmTestResponse(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}
}

func TestFCMSenderUsesScopedOAuthAndCachesToken(t *testing.T) {
	now := time.Date(2026, 11, 18, 20, 0, 0, 0, time.UTC)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oid := fcmCredentials{ClientEmail: "relay@test-project.iam.gserviceaccount.com", PrivateKeyID: "fixture-key"}
	oauthCalls, messages := 0, 0
	transport := fcmTestTransport(func(r *http.Request) (*http.Response, error) {
		switch r.URL.String() {
		case fcmOAuthURL:
			oauthCalls++
			if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
				t.Fatalf("invalid grant request: %v", err)
			}
			parts := strings.Split(r.Form.Get("assertion"), ".")
			if len(parts) != 3 {
				t.Fatal("invalid JWT")
			}
			signature, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if err := rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hash[:], signature); err != nil {
				t.Fatal(err)
			}
			claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatal(err)
			}
			var claims fcmJWTClaims
			if err := json.Unmarshal(claimsJSON, &claims); err != nil {
				t.Fatal(err)
			}
			if claims.Issuer != oid.ClientEmail || claims.Scope != "https://www.googleapis.com/auth/firebase.messaging" ||
				claims.Audience != fcmOAuthURL || claims.IssuedAt != now.Unix() || claims.ExpiresAt != now.Add(time.Hour).Unix() {
				t.Fatalf("unexpected OAuth claim scope: %+v", claims)
			}
			return fcmTestResponse(http.StatusOK, `{"access_token":"test-oauth","token_type":"Bearer","expires_in":3600}`), nil
		case "https://fcm.googleapis.com/v1/projects/test-project/messages:send":
			messages++
			if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer test-oauth" ||
				r.Header.Get("Content-Type") != "application/json" {
				t.Fatal("misconfigured message request")
			}
			var body fcmSendRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			got := body.Message
			if got.Token != "test-registration-token" || got.Android.TTL != "90s" ||
				got.Notification.Title == "" || got.Notification.Body == "" ||
				got.Data["version"] != "1" || got.Data["analyzer_id"] != "analyzer" ||
				got.Data["subscription_id"] != "sub" || got.Data["event_id"] != "event" ||
				got.Data["kind"] != "node.heard_again" || got.Data["node_pubkey"] != strings.Repeat("a", 64) {
				t.Fatalf("unexpected message: %+v", got)
			}
			return fcmTestResponse(http.StatusOK, `{"name":"projects/test-project/messages/example"}`), nil
		default:
			t.Fatalf("unexpected destination %s", r.URL)
			return nil, nil
		}
	})
	sender := newFCMClient("test-project", oid, key, transport, func() time.Time { return now }, "staging")
	job := Job{Provider: "fcm", Environment: "staging", Token: "test-registration-token", AnalyzerID: "analyzer",
		Request: DeliveryRequest{EventID: "event", SubscriptionID: "sub", Kind: "node.heard_again",
			NodePubkey: strings.Repeat("a", 64), ExpiresAt: now.Add(90 * time.Second)}}
	for range 2 {
		if result := sender.send(context.Background(), job); result.Status != sendAccepted {
			t.Fatalf("send: %+v", result)
		}
	}
	job.Environment = "production"
	if result := sender.send(context.Background(), job); result.Status != sendRejected {
		t.Fatalf("production send: %+v", result)
	}
	if oauthCalls != 1 || messages != 2 {
		t.Fatalf("OAuth calls=%d FCM messages=%d", oauthCalls, messages)
	}
	production := newFCMClient("test-project", oid, key, transport, func() time.Time { return now }, "production")
	if result := production.send(context.Background(), job); result.Status != sendAccepted {
		t.Fatalf("production sender: %+v", result)
	}
	job.Environment = "staging"
	if result := production.send(context.Background(), job); result.Status != sendRejected || oauthCalls != 2 || messages != 3 {
		t.Fatalf("production sender handling staging token: %+v, OAuth calls=%d FCM messages=%d", result, oauthCalls, messages)
	}
}

func TestFCMOnlyUnregisteredInvalidatesToken(t *testing.T) {
	now := time.Date(2026, 11, 18, 20, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name       string
		status     int
		body       string
		retryAfter string
		want       SendResult
	}{
		{"explicit unregistered", 404, `{"error":{"details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}`, "", SendResult{Status: sendInvalidToken}},
		{"unknown project", 404, `{"error":{"status":"NOT_FOUND"}}`, "", SendResult{Status: sendRejected}},
		{"wrong detail", 404, `{"error":{"details":[{"@type":"other","errorCode":"UNREGISTERED"}]}}`, "", SendResult{Status: sendRejected}},
		{"invalid argument", 400, `{"error":{"details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"INVALID_ARGUMENT"}]}}`, "", SendResult{Status: sendRejected}},
		{"throttled", 429, "{}", "", SendResult{Status: sendRetry, RetryAfter: time.Minute}},
		{"provider retry", 503, "{}", now.Add(75 * time.Second).Format(http.TimeFormat), SendResult{Status: sendRetry, RetryAfter: 75 * time.Second}},
		{"provider internal error", 500, "{}", "11", SendResult{Status: sendRetry, RetryAfter: 11 * time.Second}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := fcmClassifyResponse(tc.status, []byte(tc.body), tc.retryAfter, now)
			if got != tc.want {
				t.Fatalf("result = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestFCMRefreshesRejectedOAuthCredentialOnce(t *testing.T) {
	now := time.Date(2026, 11, 18, 20, 0, 0, 0, time.UTC)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	oauthCalls, sends := 0, 0
	transport := fcmTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() == fcmOAuthURL {
			oauthCalls++
			return fcmTestResponse(http.StatusOK, `{"access_token":"replacement","token_type":"Bearer","expires_in":3600}`), nil
		}
		sends++
		if sends == 1 {
			if r.Header.Get("Authorization") != "Bearer stale" {
				t.Fatal("cached credential was not used first")
			}
			return fcmTestResponse(http.StatusUnauthorized, "{}"), nil
		}
		if r.Header.Get("Authorization") != "Bearer replacement" {
			t.Fatal("OAuth credential was not rotated")
		}
		return fcmTestResponse(http.StatusUnauthorized, "{}"), nil
	})
	sender := newFCMClient("test-project", fcmCredentials{ClientEmail: "relay@test-project.iam.gserviceaccount.com"},
		key, transport, func() time.Time { return now }, "staging")
	sender.token, sender.refreshAt = "stale", now.Add(time.Hour)
	job := Job{Provider: "fcm", Environment: "staging", Token: "synthetic", Request: DeliveryRequest{ExpiresAt: now.Add(time.Minute)}}
	if result := sender.send(context.Background(), job); result.Status != sendRejected || oauthCalls != 1 || sends != 2 {
		t.Fatalf("unexpected response or requests: %+v OAuth=%d FCM=%d", result, oauthCalls, sends)
	}
}

func TestFCMSenderRequiresMatchingStagingProject(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "staging-account.json")
	config, err := json.Marshal(fcmCredentials{
		Type: "service_account", ProjectID: "test-project", ClientEmail: "relay@test-project.iam.gserviceaccount.com",
		PrivateKeyID: "fixture", PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"other-project", "test-project/foreign"} {
		if _, err := newFCMSender(id, path, "staging", ""); err == nil {
			t.Fatalf("accepted unexpected project %q", id)
		}
	}
	if _, err := newFCMSender("test-project", path, "staging", ""); err != nil {
		t.Fatal(err)
	}
}
