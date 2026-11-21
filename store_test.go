package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testRelayStore(t *testing.T) (*Store, *time.Time, string) {
	t.Helper()
	now := time.Date(2026, 11, 18, 20, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "relay.json")
	s, err := OpenStore(path, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return s, &now, path
}

func testAnalyzer(t *testing.T, s *Store, host string) Enrollment {
	t.Helper()
	code, err := s.IssueCode("https://" + host)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := s.Enroll(code, "request_1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enroll(code, "request_1"); apiStatus(err) != 410 {
		t.Fatalf("reused code: %v", err)
	}
	return enrollment
}

func apiStatus(err error) int {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status
	}
	return 0
}

func TestStoreLinkScopesAndReplaces(t *testing.T) {
	s, now, _ := testRelayStore(t)
	first := testAnalyzer(t, s, "first.example.test")
	second := testAnalyzer(t, s, "second.example.test")
	phone, err := s.RegisterInstallation(InstallRequest{Provider: "apns", Environment: "development", Token: "phone-token"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegisterInstallation(InstallRequest{Provider: "apns", Environment: "development", Token: "phone-token"}); apiStatus(err) != 409 {
		t.Fatalf("claimed token: %v", err)
	}
	proof, err := s.LinkProof(phone.InstallationID, phone.InstallationCredential, first.AnalyzerID)
	if err != nil {
		t.Fatal(err)
	}
	req := LinkRequest{InstallationID: phone.InstallationID, BindingID: "binding_1", Proof: proof.Proof}
	if _, err := s.Link(second.SenderCredential, req); apiStatus(err) != 404 {
		t.Fatalf("other analyzer consumed proof: %v", err)
	}
	subscription, err := s.Link(first.SenderCredential, req)
	if err != nil || !subscription.ExpiresAt.Equal(now.Add(30*24*time.Hour)) {
		t.Fatalf("link: %v, %v", subscription, err)
	}
	if again, err := s.Link(first.SenderCredential, req); err != nil || again != subscription {
		t.Fatalf("link replay: %v, %v", again, err)
	}
	req.BindingID = "binding_2"
	if _, err := s.Link(first.SenderCredential, req); apiStatus(err) != 409 {
		t.Fatalf("redeemed proof used for another binding: %v", err)
	}
	event := DeliveryRequest{EventID: "event_1", SubscriptionID: subscription.SubscriptionID,
		Kind: "node.not_heard", NodePubkey: strings.Repeat("a", 64), OccurredAt: *now, ExpiresAt: now.Add(time.Hour)}
	if _, created, err := s.Deliver(first.SenderCredential, event); err != nil || !created {
		t.Fatalf("queue event: %t, %v", created, err)
	}
	proof, err = s.LinkProof(phone.InstallationID, phone.InstallationCredential, first.AnalyzerID)
	if err != nil {
		t.Fatal(err)
	}
	req.Proof = proof.Proof
	replacement, err := s.Link(first.SenderCredential, req)
	if err != nil || replacement.SubscriptionID == subscription.SubscriptionID {
		t.Fatalf("relink: %v, %v", replacement, err)
	}
	if _, ok, err := s.Next(); err != nil || ok {
		t.Fatalf("relink kept obsolete queued job: %t, %v", ok, err)
	}
	event.SubscriptionID = replacement.SubscriptionID
	if err := s.RevokeSubscription(second.SenderCredential, replacement.SubscriptionID); apiStatus(err) != 404 {
		t.Fatalf("other analyzer revoked subscription: %v", err)
	}
	if err := s.RevokeSubscription(phone.InstallationCredential, replacement.SubscriptionID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Deliver(first.SenderCredential, event); apiStatus(err) != 410 {
		t.Fatalf("revoked subscription accepted: %v", err)
	}
}

func TestStoreDeliverySurvivesRestartAndTokenRotation(t *testing.T) {
	s, now, path := testRelayStore(t)
	analyzer := testAnalyzer(t, s, "analyzer.example.test")
	phone, err := s.RegisterInstallation(InstallRequest{Provider: "fcm", Environment: "staging", Token: "initial-provider-token"})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := s.LinkProof(phone.InstallationID, phone.InstallationCredential, analyzer.AnalyzerID)
	if err != nil {
		t.Fatal(err)
	}
	subscription, err := s.Link(analyzer.SenderCredential, LinkRequest{InstallationID: phone.InstallationID, BindingID: "binding", Proof: proof.Proof})
	if err != nil {
		t.Fatal(err)
	}
	event := DeliveryRequest{EventID: "event_1", SubscriptionID: subscription.SubscriptionID,
		Kind: "node.heard_again", NodePubkey: strings.Repeat("f", 64), OccurredAt: *now, ExpiresAt: now.Add(time.Hour)}
	delivery, created, err := s.Deliver(analyzer.SenderCredential, event)
	if err != nil || !created {
		t.Fatalf("queue: %v, %v", delivery, err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{analyzer.SenderCredential, phone.InstallationCredential, proof.Proof} {
		if strings.Contains(string(before), secret) {
			t.Fatal("persisted cleartext bearer credential or proof")
		}
	}
	s, err = OpenStore(path, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	if replay, created, err := s.Deliver(analyzer.SenderCredential, event); err != nil || created || replay != delivery {
		t.Fatalf("queue replay after restart: %v %v %v", replay, created, err)
	}
	badReplay := event
	badReplay.Kind = "node.not_heard"
	if _, _, err := s.Deliver(analyzer.SenderCredential, badReplay); apiStatus(err) != 409 {
		t.Fatalf("accepted mismatched replay: %v", err)
	}
	job, ok, err := s.Next()
	if err != nil || !ok || job.Token != "initial-provider-token" {
		t.Fatalf("claim: %t, %v", ok, err)
	}
	if err := s.UpdateToken(phone.InstallationID, phone.InstallationCredential, TokenRequest{Token: "replacement-provider-token"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Finish(job, SendResult{Status: sendInvalidToken}); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(10 * time.Second)
	job, ok, err = s.Next()
	if err != nil || !ok || job.Token != "replacement-provider-token" {
		t.Fatalf("claim after token rotation: %t, %v", ok, err)
	}
	if err := s.Finish(job, SendResult{Status: sendRetry, RetryAfter: 20 * time.Second}); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.Next(); err != nil || ok {
		t.Fatalf("retry before due: %t %v", ok, err)
	}
	*now = now.Add(20 * time.Second)
	job, ok, err = s.Next()
	if err != nil || !ok {
		t.Fatalf("retry after due: %t %v", ok, err)
	}
	if err := s.Finish(job, SendResult{Status: sendAccepted}); err != nil {
		t.Fatal(err)
	}
	if replay, _, err := s.Deliver(analyzer.SenderCredential, event); err != nil || replay.Status != "accepted" {
		t.Fatalf("accepted status: %v %v", replay, err)
	}
}
