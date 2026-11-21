package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

func testSenderCredential(i int) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(i)}, 32))
}

func testDelivery(sub, event string, now time.Time) DeliveryRequest {
	return DeliveryRequest{
		EventID: event, SubscriptionID: sub, Kind: "node.not_heard", NodePubkey: strings.Repeat("a", 64),
		OccurredAt: now, ExpiresAt: now.Add(30 * time.Minute),
	}
}

// testSubscription registers an installation and links it to analyzer.
func testSubscription(t *testing.T, s *Store, analyzer Enrollment, token string) (Installation, Subscription) {
	t.Helper()
	phone, err := s.RegisterInstallation(InstallRequest{Provider: "apns", Environment: "development", Token: token})
	if err != nil {
		t.Fatal(err)
	}
	proof, err := s.LinkProof(phone.InstallationID, phone.InstallationCredential, analyzer.AnalyzerID)
	if err != nil {
		t.Fatal(err)
	}
	sub, err := s.Link(analyzer.SenderCredential, LinkRequest{InstallationID: phone.InstallationID, BindingID: "binding_" + token, Proof: proof.Proof})
	if err != nil {
		t.Fatal(err)
	}
	return phone, sub
}

func TestRegistrableDomain(t *testing.T) {
	for origin, want := range map[string]string{
		"https://analyzer.meshtexas.org":    "meshtexas.org",
		"https://a.b.c.example.com":         "example.com",
		"https://mesh.example.co.uk":        "example.co.uk",
		"https://x.mesh.example.com.br":     "example.com.br",
		"https://example.org":               "example.org",
		"https://one.duckdns.org":           "duckdns.org",
		"https://scope.example.de":          "example.de",
		"https://deep.sub.example.org:8443": "example.org",
	} {
		if got := registrableDomain(origin); got != want {
			t.Errorf("registrableDomain(%s) = %s, want %s", origin, got, want)
		}
	}
}

// Wildcard DNS proves any number of origins; the per-domain daily rate keeps
// one domain from filling the analyzer cap.
func TestSelfEnrollmentRateIsPerDomainPerDay(t *testing.T) {
	s, now, _ := testRelayStore(t)
	for i, host := range []string{"a.example.org", "b.example.org"} {
		if _, err := s.enrollVerifiedOrigin("https://"+host, testSenderCredential(i+1)); err != nil {
			t.Fatalf("%s: %v", host, err)
		}
	}
	if _, err := s.enrollVerifiedOrigin("https://c.example.org", testSenderCredential(3)); apiStatus(err) != 429 {
		t.Fatalf("third origin on one domain: %v", err)
	}
	if _, err := s.enrollVerifiedOrigin("https://scope.other.org", testSenderCredential(4)); err != nil {
		t.Fatalf("another domain was blocked: %v", err)
	}
	// Operator-issued codes are not rate limited per domain.
	testAnalyzer(t, s, "operator.example.org")
	*now = now.Add(24*time.Hour + time.Minute)
	if _, err := s.enrollVerifiedOrigin("https://c.example.org", testSenderCredential(3)); err != nil {
		t.Fatalf("a day later: %v", err)
	}
}

// Revoked analyzers no longer hold one of the active slots.
func TestRevokedAnalyzersFreeTheirSlot(t *testing.T) {
	s, _, _ := testRelayStore(t)
	var first Enrollment
	for i := range relayMaxAnalyzers {
		e, err := s.enrollVerifiedOrigin(fmt.Sprintf("https://scope.domain%d.org", i), testSenderCredential(i))
		if err != nil {
			t.Fatalf("analyzer %d: %v", i, err)
		}
		if i == 0 {
			first = e
		}
	}
	if _, err := s.enrollVerifiedOrigin("https://scope.full.org", testSenderCredential(200)); apiStatus(err) != 429 {
		t.Fatalf("over the active cap: %v", err)
	}
	if err := s.RevokeAnalyzer(first.SenderCredential); err != nil {
		t.Fatal(err)
	}
	if _, err := s.enrollVerifiedOrigin("https://scope.full.org", testSenderCredential(200)); err != nil {
		t.Fatalf("revoked analyzer still holds its slot: %v", err)
	}
}

// Proofs are limited per installation; one installation at its quota does
// not stop another, and expired unused proofs stop counting at once.
func TestLinkProofQuotaIsPerInstallation(t *testing.T) {
	s, now, _ := testRelayStore(t)
	analyzer := testAnalyzer(t, s, "scope.example.org")
	register := func(token string) Installation {
		phone, err := s.RegisterInstallation(InstallRequest{Provider: "apns", Environment: "development", Token: token})
		if err != nil {
			t.Fatal(err)
		}
		return phone
	}
	greedy, other := register("greedy-token"), register("other-token")
	for range relayMaxUnusedProofs {
		if _, err := s.LinkProof(greedy.InstallationID, greedy.InstallationCredential, analyzer.AnalyzerID); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.LinkProof(greedy.InstallationID, greedy.InstallationCredential, analyzer.AnalyzerID); apiStatus(err) != 429 {
		t.Fatalf("over the per-installation quota: %v", err)
	}
	if _, err := s.LinkProof(other.InstallationID, other.InstallationCredential, analyzer.AnalyzerID); err != nil {
		t.Fatalf("another installation was blocked: %v", err)
	}
	*now = now.Add(relayProofLifetime + time.Second)
	if _, err := s.LinkProof(greedy.InstallationID, greedy.InstallationCredential, analyzer.AnalyzerID); err != nil {
		t.Fatalf("expired proofs still count: %v", err)
	}
	// Every earlier proof was unused and has expired: only the new one stays.
	if n := len(s.state.Proofs); n != 1 {
		t.Fatalf("expired unused proofs kept: %d proofs", n)
	}
}

// One analyzer at its delivery limit does not stop another analyzer, and
// deliveries are removed an hour after their event expired.
func TestDeliveryLimitsArePerAnalyzerAndDeliveriesArePruned(t *testing.T) {
	s, now, _ := testRelayStore(t)
	busy, quiet := testAnalyzer(t, s, "busy.example.org"), testAnalyzer(t, s, "quiet.example.net")
	var busySubs []Subscription
	for i := range 11 {
		_, sub := testSubscription(t, s, busy, fmt.Sprintf("busy-phone-%d", i))
		busySubs = append(busySubs, sub)
	}
	_, quietSub := testSubscription(t, s, quiet, "quiet-phone")
	for i := range 120 {
		sub := busySubs[i%len(busySubs)]
		if _, _, err := s.Deliver(busy.SenderCredential, testDelivery(sub.SubscriptionID, fmt.Sprintf("ev_%d", i), *now)); err != nil {
			t.Fatalf("delivery %d: %v", i, err)
		}
	}
	if _, _, err := s.Deliver(busy.SenderCredential, testDelivery(busySubs[0].SubscriptionID, "ev_over", *now)); apiStatus(err) != 429 {
		t.Fatalf("over the hourly analyzer limit: %v", err)
	}
	if _, _, err := s.Deliver(quiet.SenderCredential, testDelivery(quietSub.SubscriptionID, "ev_quiet", *now)); err != nil {
		t.Fatalf("another analyzer was blocked: %v", err)
	}
	*now = now.Add(30*time.Minute + relayDeliveryRetention + time.Second)
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if n := len(s.state.Deliveries); n != 0 {
		t.Fatalf("%d deliveries kept past retention", n)
	}
}

func TestInstallationIdleRemoval(t *testing.T) {
	s, now, path := testRelayStore(t)
	analyzer := testAnalyzer(t, s, "scope.example.org")
	idle, err := s.RegisterInstallation(InstallRequest{Provider: "apns", Environment: "development", Token: "idle-token"})
	if err != nil {
		t.Fatal(err)
	}
	linked, _ := testSubscription(t, s, analyzer, "linked-token")

	// Off by default: nothing is removed however long it sits.
	*now = now.Add(400 * 24 * time.Hour)
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.state.Installations[idle.InstallationID]; !ok {
		t.Fatal("installation removed with idle removal off")
	}

	s.SetInstallationIdle(60 * 24 * time.Hour)
	// The linked installation's subscription has long expired too; activity
	// now resets its clock.
	if _, err := s.LinkProof(linked.InstallationID, linked.InstallationCredential, analyzer.AnalyzerID); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(24 * time.Hour)
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.state.Installations[idle.InstallationID]; ok {
		t.Fatal("idle installation kept")
	}
	if _, ok := s.state.Installations[linked.InstallationID]; !ok {
		t.Fatal("recently active installation removed")
	}
	// A removed installation answers 404 unknown_installation so the app
	// registers again; a wrong credential is still 401.
	if _, err := s.LinkProof(idle.InstallationID, idle.InstallationCredential, analyzer.AnalyzerID); apiStatus(err) != 404 {
		t.Fatalf("removed installation: %v", err)
	}
	if err := s.UpdateToken(linked.InstallationID, testSenderCredential(9), TokenRequest{Token: "x"}); apiStatus(err) != 401 {
		t.Fatalf("wrong credential: %v", err)
	}
	if _, err := s.RegisterInstallation(InstallRequest{Provider: "apns", Environment: "development", Token: "idle-token"}); err != nil {
		t.Fatalf("token of a removed installation cannot register again: %v", err)
	}
	reopened, err := OpenStore(path, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reopened.state.Installations[idle.InstallationID]; ok {
		t.Fatal("removal not persisted")
	}
}

// Records from before LastActiveAt existed are stamped, never removed on
// the first prune.
func TestPruneStampsLegacyInstallations(t *testing.T) {
	s, now, _ := testRelayStore(t)
	phone, err := s.RegisterInstallation(InstallRequest{Provider: "apns", Environment: "development", Token: "legacy-token"})
	if err != nil {
		t.Fatal(err)
	}
	legacy := s.state.Installations[phone.InstallationID]
	legacy.LastActiveAt = time.Time{}
	s.state.Installations[phone.InstallationID] = legacy
	s.SetInstallationIdle(24 * time.Hour)
	*now = now.Add(10 * 24 * time.Hour)
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	got, ok := s.state.Installations[phone.InstallationID]
	if !ok || !got.LastActiveAt.Equal(*now) {
		t.Fatalf("legacy installation: kept=%v lastActive=%v", ok, got.LastActiveAt)
	}
}

func TestProviderTokenShapeInRealModes(t *testing.T) {
	s, _, _ := testRelayStore(t)
	s.mode = "production"
	for _, c := range []struct {
		provider, token string
		ok              bool
	}{
		{"apns", strings.Repeat("ab", 32), true},
		{"apns", strings.Repeat("zz", 32), false},
		{"apns", "abcd", false},
		{"fcm", "fixture:" + strings.Repeat("A", 40), true},
		{"fcm", "short-token", false},
		{"fcm", "has space " + strings.Repeat("A", 40), false},
	} {
		if got := s.validProviderToken(c.provider, c.token); got != c.ok {
			t.Errorf("validProviderToken(%s, %q) = %v, want %v", c.provider, c.token, got, c.ok)
		}
	}
	s.mode = "simulate"
	if !s.validProviderToken("apns", "readable-fixture") {
		t.Error("simulation rejected a readable fixture token")
	}
}
