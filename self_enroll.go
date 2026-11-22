package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	selfEnrollmentProofPath = "/api/push-relay/enrollment-proof"
	// CoreScope builds from before the push relay rename serve the proof here.
	legacyEnrollmentProofPath   = "/api/nodescope/enrollment-proof"
	selfEnrollmentTimeout       = 5 * time.Second
	selfEnrollmentResponseLimit = 1024
	selfEnrollmentDNSLimit      = 16
)

type enrollmentProofFetcher func(context.Context, string, string) ([]byte, error)

var dnsLabelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

func selfEnrollmentOrigin(raw string) (string, error) {
	canonical, err := canonicalOrigin(raw)
	if err != nil {
		return "", err
	}
	canonical = enrollmentOriginKey(canonical)
	origin, err := url.Parse(canonical)
	if err != nil {
		return "", storeError(http.StatusBadRequest, "invalid_origin")
	}
	name := origin.Hostname()
	labels := strings.Split(name, ".")
	if len(labels) < 2 || len(name) > 253 || origin.Host != name ||
		strings.HasSuffix(name, ".local") || strings.HasSuffix(name, ".localhost") ||
		strings.HasSuffix(name, ".onion") || strings.HasSuffix(name, ".internal") ||
		strings.HasSuffix(name, ".home.arpa") {
		return "", storeError(http.StatusBadRequest, "invalid_origin")
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return "", storeError(http.StatusBadRequest, "invalid_origin")
	}
	for _, label := range labels {
		if !dnsLabelPattern.MatchString(label) {
			return "", storeError(http.StatusBadRequest, "invalid_origin")
		}
	}
	return canonical, nil
}

func canonicalProofEncoding(value string, size int) ([]byte, bool) {
	encoding := base64.RawURLEncoding.Strict()
	if len(value) != encoding.EncodedLen(size) {
		return nil, false
	}
	decoded, err := encoding.DecodeString(value)
	return decoded, err == nil && len(decoded) == size && encoding.EncodeToString(decoded) == value
}

func (api *relayHTTP) selfEnroll(w http.ResponseWriter, r *http.Request) {
	if !relayPublicRate(w, &api.selfEnrollLimit) {
		return
	}
	req, ok := relayDecode[struct {
		Origin           string `json:"origin"`
		PublicKey        string `json:"public_key"`
		SenderCredential string `json:"sender_credential"`
	}](w, r)
	if !ok {
		return
	}
	origin, err := selfEnrollmentOrigin(req.Origin)
	if err != nil {
		relayStoreError(w, err)
		return
	}
	key, ok := canonicalProofEncoding(req.PublicKey, ed25519.PublicKeySize)
	_, validCredential := canonicalProofEncoding(req.SenderCredential, 32)
	if !ok || !validCredential {
		relayError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	select {
	case api.selfEnrollSlots <- struct{}{}:
		defer func() { <-api.selfEnrollSlots }()
	default:
		relayRetryAfter(w, selfEnrollmentTimeout)
		relayError(w, http.StatusTooManyRequests, "rate_limited")
		return
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		relayError(w, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), selfEnrollmentTimeout)
	defer cancel()
	signature, err := api.fetchEnrollmentProof(ctx, origin, base64.RawURLEncoding.EncodeToString(challenge))
	if err != nil || !ed25519.Verify(ed25519.PublicKey(key), challenge, signature) {
		relayError(w, http.StatusUnprocessableEntity, "origin_verification_failed")
		return
	}
	if err := ctx.Err(); err != nil {
		relayError(w, http.StatusUnprocessableEntity, "origin_verification_failed")
		return
	}
	enrollment, err := api.store.enrollVerifiedOrigin(origin, req.SenderCredential)
	if err != nil {
		relayStoreError(w, err)
		return
	}
	relayJSON(w, http.StatusCreated, enrollment)
}

// IsGlobalUnicast alone includes shared, benchmarking and reserved ranges.
// Restrict IPv6 to the global allocation and exclude special-use space.
var blockedEnrollmentNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
}

var globalEnrollmentIPv6 = netip.MustParsePrefix("2000::/3")

func publicEnrollmentAddress(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.Zone() != "" || !addr.IsGlobalUnicast() || addr.IsPrivate() ||
		(addr.Is6() && !globalEnrollmentIPv6.Contains(addr)) {
		return false
	}
	for _, block := range blockedEnrollmentNetworks {
		if block.Contains(addr) {
			return false
		}
	}
	return true
}

func enrollmentProofAddresses(addresses []netip.Addr) bool {
	if len(addresses) == 0 || len(addresses) > selfEnrollmentDNSLimit {
		return false
	}
	for _, address := range addresses {
		if !publicEnrollmentAddress(address) {
			return false
		}
	}
	return true
}

func fetchPublicEnrollmentProof(ctx context.Context, origin, challenge string) ([]byte, error) {
	u, err := url.Parse(origin)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	// Use an absolute DNS lookup, then dial only the addresses checked here.
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host+".")
	if err != nil || !enrollmentProofAddresses(addresses) {
		return nil, errors.New("origin must resolve only to public addresses")
	}

	dialer := net.Dialer{Timeout: 750 * time.Millisecond}
	transport := &http.Transport{
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 8 << 10,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != net.JoinHostPort(host, "443") {
				return nil, errors.New("unexpected proof destination")
			}
			for _, ip := range addresses {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), "443"))
				if err == nil {
					return conn, nil
				}
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
			}
			return nil, errors.New("could not connect to origin")
		},
	}
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	u.RawQuery = url.Values{"challenge": {challenge}}.Encode()
	return requestEnrollmentProof(ctx, client, *u)
}

// requestEnrollmentProof asks the current proof path first and the legacy
// path only when the analyzer answers 404, so an older CoreScope can still
// enroll. Any other failure ends the attempt.
func requestEnrollmentProof(ctx context.Context, client *http.Client, u url.URL) ([]byte, error) {
	for _, path := range []string{selfEnrollmentProofPath, legacyEnrollmentProofPath} {
		u.Path = path
		signature, status, err := getEnrollmentProof(ctx, client, u.String())
		if status == http.StatusNotFound {
			continue
		}
		return signature, err
	}
	return nil, errors.New("analyzer serves no enrollment proof")
}

func getEnrollmentProof(ctx context.Context, client *http.Client, target string) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || err != nil || mediaType != "application/json" {
		return nil, response.StatusCode, errors.New("invalid proof response")
	}
	signature, err := decodeEnrollmentProof(response.Body)
	return signature, response.StatusCode, err
}

func decodeEnrollmentProof(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, selfEnrollmentResponseLimit+1))
	if err != nil || len(body) > selfEnrollmentResponseLimit {
		return nil, errors.New("oversized or unreadable proof")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var result struct {
		Signature string `json:"signature"`
	}
	// Require one complete JSON object.
	if err := decoder.Decode(&result); err != nil {
		return nil, errors.New("invalid proof response")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("invalid proof response")
	}
	signature, ok := canonicalProofEncoding(result.Signature, ed25519.SignatureSize)
	if !ok {
		return nil, errors.New("invalid proof signature")
	}
	return signature, nil
}
