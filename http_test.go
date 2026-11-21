package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func relayHTTPTestRequest(t *testing.T, h http.Handler, method, path, body, token string, want int) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != want {
		t.Fatalf("%s %s: status %d, want %d (%s)", method, path, w.Code, want, w.Body.String())
	}
	return w
}

func relayHTTPDecode[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestRelayHTTPEnrollmentAndRevocation(t *testing.T) {
	now := time.Date(2026, 11, 18, 20, 0, 0, 0, time.UTC)
	store, err := OpenStore(filepath.Join(t.TempDir(), "relay.json"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(store, "test-operator")
	const endpoint = "/v1/operator/enrollment-codes"
	const origin = "https://analyzer-staging.nodescope.app"
	body := `{"origin":"` + origin + `"}`
	relayHTTPTestRequest(t, NewHandler(store, ""), http.MethodPost, endpoint, body, "", http.StatusNotFound)
	relayHTTPTestRequest(t, h, http.MethodGet, "/healthz", "", "", http.StatusOK)
	relayHTTPTestRequest(t, h, http.MethodPost, endpoint, body, "wrong", http.StatusUnauthorized)
	w := relayHTTPTestRequest(t, h, http.MethodPost, endpoint, body, "test-operator", http.StatusCreated)
	code := relayHTTPDecode[struct{ Code string }](t, w).Code
	if code == "" {
		t.Fatal("empty enrollment code")
	}
	enrollmentBody := `{"code":"` + code + `","request_id":"req_test"}`
	w = relayHTTPTestRequest(t, h, http.MethodPost, "/v1/analyzers/enroll", enrollmentBody, "", http.StatusCreated)
	link := relayHTTPDecode[struct {
		ID         string `json:"analyzer_id"`
		Credential string `json:"sender_credential"`
	}](t, w)
	if link.ID == "" || link.Credential == "" {
		t.Fatal("incomplete enrollment")
	}
	relayHTTPTestRequest(t, h, http.MethodGet, "/v1/analyzer", "", "wrong", http.StatusUnauthorized)
	w = relayHTTPTestRequest(t, h, http.MethodGet, "/v1/analyzer", "", link.Credential, http.StatusOK)
	analyzer := relayHTTPDecode[struct {
		ID      string `json:"analyzer_id"`
		Origin  string
		Version int `json:"contract_version"`
	}](t, w)
	if analyzer.ID != link.ID || analyzer.Origin != origin || analyzer.Version != 1 {
		t.Fatalf("incorrect analyzer identity or version: %+v", analyzer)
	}
	if strings.Contains(w.Body.String(), link.Credential) || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("analyzer response exposed a credential or caching was enabled")
	}
	w = relayHTTPTestRequest(t, h, http.MethodPost, "/v1/installations",
		`{"provider":"apns","environment":"development","token":"`+strings.Repeat("a", 64)+`"}`, "", http.StatusCreated)
	phone := relayHTTPDecode[Installation](t, w)
	tokenPath := "/v1/installations/" + phone.InstallationID + "/token"
	tokenBody := `{"token":"` + strings.Repeat("b", 64) + `"}`
	relayHTTPTestRequest(t, h, http.MethodPut, tokenPath, tokenBody, "", http.StatusUnauthorized)
	relayHTTPTestRequest(t, h, http.MethodPut, tokenPath, tokenBody, phone.InstallationCredential, http.StatusNoContent)
	proofPath := "/v1/installations/" + phone.InstallationID + "/link-proofs"
	w = relayHTTPTestRequest(t, h, http.MethodPost, proofPath, `{"analyzer_id":"`+link.ID+`"}`, phone.InstallationCredential, http.StatusCreated)
	proof := relayHTTPDecode[Proof](t, w)
	subscriptionBody, err := json.Marshal(LinkRequest{InstallationID: phone.InstallationID, BindingID: "binding_test", Proof: proof.Proof})
	if err != nil {
		t.Fatal(err)
	}
	w = relayHTTPTestRequest(t, h, http.MethodPost, "/v1/subscriptions", string(subscriptionBody), link.Credential, http.StatusCreated)
	subscription := relayHTTPDecode[Subscription](t, w)
	if subscription.Status != "active" || subscription.SubscriptionID == "" {
		t.Fatalf("unexpected subscription: %+v", subscription)
	}
	event := DeliveryRequest{
		EventID: "event_test", SubscriptionID: subscription.SubscriptionID, Kind: "node.heard_again",
		NodePubkey: strings.Repeat("3", 64), NodeName: "Milliways 1W", OccurredAt: now, ExpiresAt: now.Add(time.Hour),
	}
	payload, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	w = relayHTTPTestRequest(t, h, http.MethodPost, "/v1/deliveries", string(payload), link.Credential, http.StatusAccepted)
	first := relayHTTPDecode[Delivery](t, w)
	w = relayHTTPTestRequest(t, h, http.MethodPost, "/v1/deliveries", string(payload), link.Credential, http.StatusOK)
	if replay := relayHTTPDecode[Delivery](t, w); replay.DeliveryID == "" || replay != first {
		t.Fatalf("unexpected delivery replay: %+v", replay)
	}
	relayHTTPTestRequest(t, h, http.MethodDelete, "/v1/subscriptions/"+subscription.SubscriptionID, "", phone.InstallationCredential, http.StatusNoContent)
	event.EventID = "event_after_revoke"
	payload, err = json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	relayHTTPTestRequest(t, h, http.MethodPost, "/v1/deliveries", string(payload), link.Credential, http.StatusGone)
	relayHTTPTestRequest(t, h, http.MethodDelete, "/v1/analyzer", "", link.Credential, http.StatusNoContent)
	relayHTTPTestRequest(t, h, http.MethodGet, "/v1/analyzer", "", link.Credential, http.StatusGone)
}

func TestRelayHTTPRejectsMalformedAndUnknownRequests(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "relay.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(store, "test-operator")
	const endpoint = "/v1/analyzers/enroll"
	for _, invalid := range []string{
		`{"code":"secret","request_id":"a","other":true}`,
		`{"code":"secret","request_id":"a"} {}`,
		`{"code":"` + strings.Repeat("a", relayMaxRequest+1) + `"}`,
	} {
		w := relayHTTPTestRequest(t, h, http.MethodPost, endpoint, invalid, "", http.StatusBadRequest)
		failure := relayHTTPDecode[relayErrorResponse](t, w)
		if failure.Error.Code != "invalid_request" || strings.Contains(w.Body.String(), "secret") {
			t.Fatal("unsafe error response")
		}
	}
	relayHTTPTestRequest(t, h, http.MethodGet, "/v2/analyzer", "", "", http.StatusNotFound)
	relayHTTPTestRequest(t, h, http.MethodGet, endpoint, "", "", http.StatusMethodNotAllowed)
	relayHTTPTestRequest(t, h, http.MethodPost, "/v1/deliveries", "{}", "", http.StatusUnauthorized)
}

func TestRelayHTTPPublicWritesAreRateLimitedIndependently(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "relay.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(store, "")
	for range 30 {
		relayHTTPTestRequest(t, h, http.MethodPost, "/v1/analyzers/enroll", "{}", "", http.StatusBadRequest)
	}
	w := relayHTTPTestRequest(t, h, http.MethodPost, "/v1/analyzers/enroll", "{}", "", http.StatusTooManyRequests)
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("rate limited response did not contain Retry-After")
	}
	relayHTTPTestRequest(t, h, http.MethodPost, "/v1/installations", "{}", "", http.StatusBadRequest)
}

func TestSecondAnalyzerCanEnrollAfterExpiredCodeAndCannotUseFirstSubscription(t *testing.T) {
	now := time.Date(2026, 11, 18, 20, 0, 0, 0, time.UTC)
	store, err := OpenStore(filepath.Join(t.TempDir(), "relay.json"), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	h := NewHandler(store, "test-operator")
	encode := func(value any) string {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	issue := func(origin string) string {
		t.Helper()
		w := relayHTTPTestRequest(t, h, http.MethodPost, "/v1/operator/enrollment-codes",
			encode(map[string]string{"origin": origin}), "test-operator", http.StatusCreated)
		return relayHTTPDecode[struct{ Code string }](t, w).Code
	}
	enroll := func(code, id string, status int) *httptest.ResponseRecorder {
		t.Helper()
		return relayHTTPTestRequest(t, h, http.MethodPost, "/v1/analyzers/enroll",
			encode(map[string]string{"code": code, "request_id": id}), "", status)
	}
	first := relayHTTPDecode[Enrollment](t, enroll(issue("https://first.example.test"), "first", http.StatusCreated))
	const secondOrigin = "https://second.example.test"
	expired := issue(secondOrigin)
	now = now.Add(16 * time.Minute)
	enroll(expired, "expired", http.StatusGone)
	fresh := issue(secondOrigin)
	second := relayHTTPDecode[Enrollment](t, enroll(fresh, "second", http.StatusCreated))
	enroll(fresh, "second", http.StatusGone)
	w := relayHTTPTestRequest(t, h, http.MethodGet, "/v1/analyzer", "", second.SenderCredential, http.StatusOK)
	info := relayHTTPDecode[Analyzer](t, w)
	if info.Origin != secondOrigin || info.AnalyzerID != second.AnalyzerID || info.AnalyzerID == first.AnalyzerID {
		t.Fatalf("unexpected second analyzer identity: %+v", info)
	}

	w = relayHTTPTestRequest(t, h, http.MethodPost, "/v1/installations",
		encode(InstallRequest{Provider: "apns", Environment: "development", Token: strings.Repeat("a", 64)}),
		"", http.StatusCreated)
	phone := relayHTTPDecode[Installation](t, w)
	link := func(source Enrollment, binding string) Subscription {
		t.Helper()
		path := "/v1/installations/" + phone.InstallationID + "/link-proofs"
		w := relayHTTPTestRequest(t, h, http.MethodPost, path,
			encode(map[string]string{"analyzer_id": source.AnalyzerID}), phone.InstallationCredential, http.StatusCreated)
		proof := relayHTTPDecode[Proof](t, w)
		w = relayHTTPTestRequest(t, h, http.MethodPost, "/v1/subscriptions",
			encode(LinkRequest{InstallationID: phone.InstallationID, BindingID: binding, Proof: proof.Proof}),
			source.SenderCredential, http.StatusCreated)
		return relayHTTPDecode[Subscription](t, w)
	}
	firstSub, secondSub := link(first, "first-binding"), link(second, "second-binding")
	deliver := func(sender Enrollment, sub Subscription, event string, status int) {
		t.Helper()
		relayHTTPTestRequest(t, h, http.MethodPost, "/v1/deliveries", encode(DeliveryRequest{
			EventID: event, SubscriptionID: sub.SubscriptionID, Kind: "node.heard_again",
			NodePubkey: strings.Repeat("b", 64), OccurredAt: now, ExpiresAt: now.Add(time.Hour),
		}), sender.SenderCredential, status)
	}
	deliver(second, firstSub, "wrong-source", http.StatusNotFound)
	deliver(second, secondSub, "second-delivery", http.StatusAccepted)
	relayHTTPTestRequest(t, h, http.MethodDelete, "/v1/analyzer", "", second.SenderCredential, http.StatusNoContent)
	deliver(second, secondSub, "after-revoke", http.StatusGone)
	if _, found, err := store.Next(); err != nil || found {
		t.Fatalf("second analyzer still has deliverable work after revocation: found=%v, err=%v", found, err)
	}
	deliver(first, firstSub, "first-still-active", http.StatusAccepted)
}
