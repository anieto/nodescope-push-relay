package main

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestRelayDispatchRetriesAndSendsToBothProviders(t *testing.T) {
	now := time.Date(2026, 11, 18, 20, 0, 0, 0, time.UTC)
	store, err := OpenStore(filepath.Join(t.TempDir(), "relay.json"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	code, err := store.IssueCode("https://analyzer-staging.nodescope.app")
	if err != nil {
		t.Fatal(err)
	}
	analyzer, err := store.Enroll(code, "enrollment_test")
	if err != nil {
		t.Fatal(err)
	}

	for i, request := range []InstallRequest{
		{Provider: "apns", Environment: "development", Token: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{Provider: "fcm", Environment: "staging", Token: "fixture_fcm_token_0123456789abcdefghijklmnop"},
	} {
		installation, err := store.RegisterInstallation(request)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := store.LinkProof(installation.InstallationID, installation.InstallationCredential, analyzer.AnalyzerID)
		if err != nil {
			t.Fatal(err)
		}
		sub, err := store.Link(analyzer.SenderCredential, LinkRequest{
			InstallationID: installation.InstallationID, BindingID: fmt.Sprintf("binding_%d", i), Proof: proof.Proof,
		})
		if err != nil {
			t.Fatal(err)
		}
		delivery := DeliveryRequest{
			EventID: "one_core_scope_transition", SubscriptionID: sub.SubscriptionID,
			Kind: "node.heard_again", NodePubkey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			OccurredAt: now, ExpiresAt: now.Add(30 * time.Minute),
		}
		first, created, err := store.Deliver(analyzer.SenderCredential, delivery)
		if err != nil || !created {
			t.Fatalf("queue: %+v, created=%v, err=%v", first, created, err)
		}
		replay, created, err := store.Deliver(analyzer.SenderCredential, delivery)
		if err != nil || created || replay.DeliveryID != first.DeliveryID {
			t.Fatalf("retry created a duplicate: %+v, created=%v, err=%v", replay, created, err)
		}
	}
	calls := map[string][]Job{}
	sender := func(_ context.Context, job Job) SendResult {
		calls[job.Provider] = append(calls[job.Provider], job)
		if job.Provider == "apns" && len(calls[job.Provider]) == 1 {
			return SendResult{Status: sendRetry, RetryAfter: time.Minute}
		}
		return SendResult{Status: sendAccepted}
	}
	if err := drainQueue(context.Background(), store, sender); err != nil {
		t.Fatal(err)
	}
	if len(calls["apns"]) != 1 || len(calls["fcm"]) != 1 {
		t.Fatalf("first drain: APNs=%d, FCM=%d", len(calls["apns"]), len(calls["fcm"]))
	}
	now = now.Add(time.Minute + time.Second)
	if err := drainQueue(context.Background(), store, sender); err != nil {
		t.Fatal(err)
	}
	if len(calls["apns"]) != 2 || len(calls["fcm"]) != 1 || calls["apns"][0].DeliveryID != calls["apns"][1].DeliveryID {
		t.Fatal("transient failure did not retry the same delivery")
	}
}
