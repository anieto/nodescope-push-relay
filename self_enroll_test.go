package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSelfEnrollmentVerifiesOriginAndSupportsSafeRetry(t *testing.T) {
	st, err := OpenStore(filepath.Join(t.TempDir(), "relay.json"), time.Now)
	if err != nil {
		t.Fatal(err)
	}
	key, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const origin = "https://analyzer.example.org"
	const selfEnroll = "/v1/analyzers/self-enroll"
	var previousChallenge string
	var previousSignature []byte
	replayProof := false
	fetch := func(_ context.Context, actualOrigin, challenge string) ([]byte, error) {
		if actualOrigin != origin || challenge == previousChallenge {
			t.Fatalf("invalid challenge request: origin %q, repeated challenge %t", actualOrigin, challenge == previousChallenge)
		}
		raw, ok := canonicalProofEncoding(challenge, 32)
		if !ok {
			t.Fatal("challenge is not an encoded 32-byte value")
		}
		if replayProof {
			return previousSignature, nil
		}
		previousChallenge = challenge
		previousSignature = ed25519.Sign(signer, raw)
		return previousSignature, nil
	}
	credential := secret()
	request := func(address string, key ed25519.PublicKey, credential string) string {
		body, err := json.Marshal(map[string]string{
			"origin": address, "public_key": base64.RawURLEncoding.EncodeToString(key), "sender_credential": credential,
		})
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	payload := request(origin, key, credential)
	relayHTTPTestRequest(t, NewHandler(st, "operator"), http.MethodPost, selfEnroll, payload, "", http.StatusNotFound)
	handler := newRelayHandler(st, "operator", fetch)

	relayHTTPTestRequest(t, handler, http.MethodPost, selfEnroll, request("https://127.0.0.1", key, credential), "", http.StatusBadRequest)
	relayHTTPTestRequest(t, handler, http.MethodPost, selfEnroll, request(origin, key, "malformed"), "", http.StatusBadRequest)
	relayHTTPTestRequest(t, handler, http.MethodPost, selfEnroll, request(origin, otherKey, credential), "", http.StatusUnprocessableEntity)

	w := relayHTTPTestRequest(t, handler, http.MethodPost, selfEnroll, request(origin+":443", key, credential), "", http.StatusCreated)
	first := relayHTTPDecode[Enrollment](t, w)
	if first.SenderCredential != credential || first.AnalyzerID == "" {
		t.Fatal("missing enrollment credentials")
	}
	w = relayHTTPTestRequest(t, handler, http.MethodGet, "/v1/analyzer", "", credential, http.StatusOK)
	if result := relayHTTPDecode[Analyzer](t, w); result.Origin != origin || result.AnalyzerID != first.AnalyzerID {
		t.Fatalf("unexpected enrolled analyzer: %+v", result)
	}

	replayProof = true
	relayHTTPTestRequest(t, handler, http.MethodPost, selfEnroll, payload, "", http.StatusUnprocessableEntity)
	replayProof = false
	w = relayHTTPTestRequest(t, handler, http.MethodPost, selfEnroll, payload, "", http.StatusCreated)
	if retry := relayHTTPDecode[Enrollment](t, w); retry != first {
		t.Fatal("safe retry changed the enrollment")
	}
	relayHTTPTestRequest(t, handler, http.MethodPost, selfEnroll, request(origin, key, secret()), "", http.StatusConflict)
	relayHTTPTestRequest(t, handler, http.MethodPost, "/v1/operator/enrollment-codes", `{"origin":"https://analyzer.example.org:443"}`, "operator", http.StatusConflict)

	relayHTTPTestRequest(t, handler, http.MethodDelete, "/v1/analyzer", "", credential, http.StatusNoContent)
	relayHTTPTestRequest(t, handler, http.MethodPost, selfEnroll, payload, "", http.StatusConflict)
	w = relayHTTPTestRequest(t, handler, http.MethodPost, selfEnroll, request(origin, key, secret()), "", http.StatusCreated)
	if fresh := relayHTTPDecode[Enrollment](t, w); fresh.AnalyzerID == first.AnalyzerID {
		t.Fatal("new enrollment reused the revoked analyzer ID")
	}
}

func TestPublicEnrollmentOriginAndAddresses(t *testing.T) {
	for _, input := range []string{
		"http://example.org", "https://example.org:8443", "https://host", "https://host.local", "https://example.org.",
		"https://user@example.org", "https://foo..example.org", "https://-foo.example.org", "https://example.org/query",
		"https://example.org/?x=1", "https://example.org/#x", "https://[::1]", "https://8.8.8.8",
	} {
		if _, err := selfEnrollmentOrigin(input); err == nil {
			t.Errorf("accepted unsupported origin %q", input)
		}
	}
	if origin, err := selfEnrollmentOrigin("https://Example.ORG:443/"); err != nil || origin != "https://example.org" {
		t.Fatalf("unexpected origin normalization: %q (%v)", origin, err)
	}

	for _, value := range []string{"8.8.8.8", "2606:4700:4700::1111"} {
		if !publicEnrollmentAddress(netip.MustParseAddr(value)) {
			t.Errorf("rejected public address %s", value)
		}
	}
	for _, value := range []string{
		"0.0.0.0", "127.0.0.1", "10.0.0.1", "172.31.0.1", "192.168.0.1", "169.254.169.254",
		"100.64.0.1", "192.0.0.9", "198.18.0.1", "192.0.2.1", "224.0.0.1", "240.0.0.1",
		"::", "::1", "::ffff:127.0.0.1", "fe80::1%en0", "fc00::1", "64:ff9b::a00:1", "2002::1",
		"2001:db8::1",
	} {
		if publicEnrollmentAddress(netip.MustParseAddr(value)) {
			t.Errorf("accepted non-public address %s", value)
		}
	}
	if enrollmentProofAddresses([]netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}) {
		t.Error("accepted mixed public and non-public DNS answers")
	}
}

func TestDecodeEnrollmentProofLimitsResponse(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	valid := `{"signature":"` + encoded + `"}`
	if signature, err := decodeEnrollmentProof(strings.NewReader(valid)); err != nil || len(signature) != ed25519.SignatureSize {
		t.Fatalf("valid proof failed to decode: %v", err)
	}
	for _, input := range []string{
		`null`, `{"signature":"short"}`, valid + `{}`,
		`{"extra":1,"signature":"` + encoded + `"}`, valid + strings.Repeat(" ", selfEnrollmentResponseLimit),
	} {
		if _, err := decodeEnrollmentProof(strings.NewReader(input)); err == nil {
			t.Errorf("accepted invalid proof response (%d bytes)", len(input))
		}
	}
}
