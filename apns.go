package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const (
	apnsProductionDeviceURL = "https://api.push.apple.com/3/device/"
	apnsSandboxDeviceURL    = "https://api.sandbox.push.apple.com/3/device/"
	apnsMaxBody             = 4096
	apnsJWTRefreshAge       = 50 * time.Minute
	apnsJWTMinRefreshAge    = 20 * time.Minute
)

var (
	apnsProviderID  = regexp.MustCompile(`^[A-Za-z0-9]{10}$`)
	apnsBundleTopic = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,254}$`)
)

type apnsSender struct {
	teamID, keyID, topic, environment, title string
	key                                      *ecdsa.PrivateKey
	client                                   *http.Client
	now                                      func() time.Time

	mu       sync.Mutex
	jwt      string
	issuedAt time.Time
}

func newAPNsSender(teamID, keyID, topic, keyPath, environment, title string) (sendPush, error) {
	if !apnsProviderID.MatchString(teamID) || !apnsProviderID.MatchString(keyID) || !apnsBundleTopic.MatchString(topic) {
		return nil, errors.New("invalid APNs team ID, key ID, or topic")
	}
	key, err := loadAPNsKey(keyPath)
	if err != nil {
		return nil, err
	}
	sender := &apnsSender{teamID: teamID, keyID: keyID, topic: topic, environment: environment, title: title, key: key, client: newAPNsClient(), now: time.Now}
	return sender.send, nil
}

func newAPNsClient() *http.Client {
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	return &http.Client{
		Transport: &http.Transport{
			Protocols:             protocols,
			TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 7 * time.Second,
			IdleConnTimeout:       5 * time.Minute,
		},
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func loadAPNsKey(path string) (*ecdsa.PrivateKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("cannot open APNs signing key file")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, apnsMaxBody+1))
	if err != nil || len(data) > apnsMaxBody {
		return nil, errors.New("cannot read APNs signing key file")
	}
	data = bytes.TrimSpace(data)
	block, rest := pem.Decode(data)
	if !bytes.HasPrefix(data, []byte("-----BEGIN PRIVATE KEY-----")) ||
		block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("APNs signing key must be a single unencrypted PKCS#8 PEM block")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("APNs signing key must be P-256")
	}
	return key, nil
}

func (s *apnsSender) providerJWT(now time.Time) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	age := now.Sub(s.issuedAt)
	if s.jwt != "" && age >= 0 && age < apnsJWTRefreshAge {
		return s.jwt, nil
	}

	header, err := json.Marshal(struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}{Alg: "ES256", Kid: s.keyID})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(struct {
		Iss string `json:"iss"`
		Iat int64  `json:"iat"`
	}{Iss: s.teamID, Iat: now.Unix()})
	if err != nil {
		return "", err
	}
	base64url := base64.RawURLEncoding
	signed := base64url.EncodeToString(header) + "." + base64url.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signed))
	r, signatureS, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return "", err
	}
	var signature [64]byte
	r.FillBytes(signature[:32])
	signatureS.FillBytes(signature[32:])
	s.jwt = signed + "." + base64url.EncodeToString(signature[:])
	s.issuedAt = now
	return s.jwt, nil
}

func (s *apnsSender) clearExpiredJWT(token string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.jwt == token && now.Sub(s.issuedAt) >= apnsJWTMinRefreshAge {
		s.jwt = ""
	}
}

func (s *apnsSender) send(ctx context.Context, job Job) SendResult {
	now := s.now()
	if job.Provider != "apns" || job.Environment != s.environment || !job.Request.ExpiresAt.After(now) ||
		!validAPNsDeviceToken(job.Token) {
		return SendResult{Status: sendRejected}
	}

	title, body := relayAlert(s.title, job)
	payload := make(map[string]any, 7)
	for name, value := range relayMetadata(job) {
		payload[name] = value
	}
	payload["aps"] = struct {
		Alert apnsAlert `json:"alert"`
	}{Alert: apnsAlert{Title: title, Body: body}}
	encoded, err := json.Marshal(payload)
	if err != nil || len(encoded) > apnsMaxBody {
		return SendResult{Status: sendRejected}
	}
	endpoint := apnsSandboxDeviceURL
	if s.environment == "production" {
		endpoint = apnsProductionDeviceURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+job.Token, bytes.NewReader(encoded))
	if err != nil {
		return SendResult{Status: sendRejected}
	}
	token, err := s.providerJWT(now)
	if err != nil {
		return SendResult{Status: sendRetry, RetryAfter: time.Minute}
	}
	req.Header.Set("authorization", "bearer "+token)
	req.Header.Set("apns-topic", s.topic)
	req.Header.Set("apns-expiration", strconv.FormatInt(job.Request.ExpiresAt.Unix(), 10))
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", "10")
	req.Header.Set("content-type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return SendResult{Status: sendRetry}
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		return SendResult{Status: sendRetry, RetryAfter: time.Minute}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, apnsMaxBody+1))
	var providerError struct {
		Reason string `json:"reason"`
	}
	if err == nil && len(data) <= apnsMaxBody && resp.StatusCode != http.StatusOK {
		// Invalid or unrecognized bodies never retire a device token.
		if json.Unmarshal(data, &providerError) != nil {
			providerError.Reason = ""
		}
	}
	if resp.StatusCode == http.StatusForbidden && providerError.Reason == "ExpiredProviderToken" {
		s.clearExpiredJWT(token, s.now())
	}
	return classifyAPNsResponse(resp, providerError.Reason, s.now())
}

type apnsAlert struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

func validAPNsDeviceToken(token string) bool {
	if len(token) < 2 || len(token) > 512 || len(token)%2 != 0 {
		return false
	}
	for i := range len(token) {
		if token[i] >= '0' && token[i] <= '9' {
			continue
		}
		switch token[i] | 0x20 {
		case 'a', 'b', 'c', 'd', 'e', 'f':
		default:
			return false
		}
	}
	return true
}

func classifyAPNsResponse(resp *http.Response, reason string, now time.Time) SendResult {
	retry := func(minimum time.Duration) SendResult {
		return SendResult{Status: sendRetry, RetryAfter: max(minimum, apnsRetryAfter(resp.Header.Get("Retry-After"), now))}
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		return SendResult{Status: sendAccepted}
	case resp.StatusCode == http.StatusGone && (reason == "Unregistered" || reason == "ExpiredToken"):
		return SendResult{Status: sendInvalidToken}
	case resp.StatusCode == http.StatusUnauthorized:
		return retry(time.Minute)
	case resp.StatusCode == http.StatusForbidden:
		switch reason {
		case "ExpiredProviderToken", "InvalidProviderToken", "MissingProviderToken", "UnrelatedKeyIdInToken", "BadEnvironmentKeyIdInToken":
			return retry(time.Minute)
		}
	case resp.StatusCode == http.StatusTooManyRequests:
		if reason == "TooManyProviderTokenUpdates" {
			return retry(20 * time.Minute)
		}
		return retry(time.Minute)
	case resp.StatusCode >= http.StatusInternalServerError:
		return retry(15 * time.Minute)
	}
	return SendResult{Status: sendRejected}
}

func apnsRetryAfter(value string, now time.Time) time.Duration {
	if seconds, err := strconv.ParseUint(value, 10, 32); err == nil {
		return time.Duration(seconds) * time.Second
	}
	if date, err := http.ParseTime(value); err == nil {
		return max(0, date.Sub(now))
	}
	return 0
}
