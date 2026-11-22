package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	fcmOAuthURL       = "https://oauth2.googleapis.com/token"
	fcmMessagingScope = "https://www.googleapis.com/auth/firebase.messaging"
	fcmMaxResponse    = 64 << 10
	fcmRequestTimeout = 8 * time.Second
)

var fcmProjectID = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

type fcmCredentials struct {
	Type         string `json:"type"`
	ProjectID    string `json:"project_id"`
	ClientEmail  string `json:"client_email"`
	PrivateKeyID string `json:"private_key_id"`
	PrivateKey   string `json:"private_key"`
}

type fcmJWTClaims struct {
	Issuer    string `json:"iss"`
	Scope     string `json:"scope"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

type fcmAccessToken struct {
	Value     string `json:"access_token"`
	TokenType string `json:"token_type"`
	ExpiresIn int64  `json:"expires_in"`
}

type fcmClient struct {
	projectID   string
	environment string
	title       string
	email       string
	keyID       string
	key         *rsa.PrivateKey
	http        *http.Client
	now         func() time.Time
	mu          sync.Mutex
	token       string
	refreshAt   time.Time
}

func newFCMSender(projectID, serviceAccountPath, environment, title string) (sendPush, error) {
	if !fcmProjectID.MatchString(projectID) {
		return nil, errors.New("invalid FCM project ID")
	}
	accountFile, err := os.Open(serviceAccountPath)
	if err != nil {
		return nil, errors.New("cannot open FCM service account file")
	}
	defer accountFile.Close()
	raw, err := io.ReadAll(io.LimitReader(accountFile, fcmMaxResponse+1))
	if err != nil || len(raw) > fcmMaxResponse {
		return nil, errors.New("cannot read FCM service account file")
	}
	var account fcmCredentials
	if err := json.Unmarshal(raw, &account); err != nil || account.Type != "service_account" ||
		account.ProjectID != projectID || account.ClientEmail == "" || account.PrivateKeyID == "" {
		return nil, errors.New("FCM service account must belong to the configured Firebase project")
	}
	block, rest := pem.Decode([]byte(account.PrivateKey))
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid FCM service account private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := parsed.(*rsa.PrivateKey)
	if err != nil || !ok || key.N.BitLen() < 2048 || key.Validate() != nil {
		return nil, errors.New("invalid FCM service account RSA key")
	}
	client := newFCMClient(projectID, account, key, nil, time.Now, environment)
	client.title = title
	return client.send, nil
}

func newFCMClient(projectID string, account fcmCredentials, key *rsa.PrivateKey, transport http.RoundTripper, now func() time.Time, environment string) *fcmClient {
	return &fcmClient{
		projectID:   projectID,
		environment: environment,
		email:       account.ClientEmail,
		keyID:       account.PrivateKeyID,
		key:         key,
		now:         now,
		http: &http.Client{
			Transport:     transport,
			Timeout:       fcmRequestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (c *fcmClient) assertion(now time.Time) (string, error) {
	header, err := json.Marshal(struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
		KeyID     string `json:"kid"`
	}{"RS256", "JWT", c.keyID})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(fcmJWTClaims{
		Issuer: c.email, Scope: fcmMessagingScope, Audience: fcmOAuthURL,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
	})
	if err != nil {
		return "", err
	}
	encoding := base64.RawURLEncoding
	input := encoding.EncodeToString(header) + "." + encoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(nil, c.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return input + "." + encoding.EncodeToString(sig), nil
}

func (c *fcmClient) accessToken(ctx context.Context) (string, SendResult) {
	now := c.now()
	c.mu.Lock()
	cached, refreshAt := c.token, c.refreshAt
	c.mu.Unlock()
	if cached != "" && now.Before(refreshAt) {
		return cached, SendResult{}
	}
	assertion, err := c.assertion(now)
	if err != nil {
		return "", SendResult{Status: sendRejected}
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fcmOAuthURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", SendResult{Status: sendRejected}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	status, raw, retry, err := c.request(req)
	if err != nil {
		return "", SendResult{Status: sendRetry}
	}
	if status != http.StatusOK {
		// Never use messaging error details from the OAuth server.
		return "", fcmClassifyResponse(status, nil, retry, c.now())
	}
	var issued fcmAccessToken
	if err := json.Unmarshal(raw, &issued); err != nil || issued.Value == "" ||
		strings.ContainsAny(issued.Value, " \t\r\n") || !strings.EqualFold(issued.TokenType, "Bearer") ||
		issued.ExpiresIn <= 0 || issued.ExpiresIn > 3600 {
		return "", SendResult{Status: sendRejected}
	}
	c.mu.Lock()
	c.token = issued.Value
	c.refreshAt = now.Add(max(0, time.Duration(issued.ExpiresIn)*time.Second-30*time.Second))
	c.mu.Unlock()
	return issued.Value, SendResult{}
}

func (c *fcmClient) invalidateAccessToken(token string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == token {
		c.token = ""
	}
}

type fcmSendRequest struct {
	Message fcmMessage `json:"message"`
}

type fcmMessage struct {
	Token        string            `json:"token"`
	Notification fcmNotification   `json:"notification"`
	Data         map[string]string `json:"data"`
	Android      fcmAndroidConfig  `json:"android"`
}

type fcmNotification struct {
	Title string `json:"title"`
	Body  string `json:"body"`
}

type fcmAndroidConfig struct {
	TTL      string `json:"ttl"`
	Priority string `json:"priority"`
}

func (c *fcmClient) send(ctx context.Context, job Job) SendResult {
	if job.Provider != "fcm" || job.Environment != c.environment || job.Token == "" ||
		!job.Request.ExpiresAt.After(c.now()) {
		return SendResult{Status: sendRejected}
	}
	for attempt := range 2 {
		token, result := c.accessToken(ctx)
		if token == "" {
			return result
		}
		seconds := job.Request.ExpiresAt.Sub(c.now()) / time.Second
		if seconds <= 0 || seconds > 3600 {
			return SendResult{Status: sendRejected}
		}
		title, body := relayAlert(c.title, job)
		request := fcmSendRequest{Message: fcmMessage{
			Token: job.Token, Notification: fcmNotification{Title: title, Body: body}, Data: relayMetadata(job),
			Android: fcmAndroidConfig{TTL: strconv.FormatInt(int64(seconds), 10) + "s", Priority: "high"},
		}}
		payload, err := json.Marshal(request)
		if err != nil {
			return SendResult{Status: sendRejected}
		}
		endpoint := "https://fcm.googleapis.com/v1/projects/" + c.projectID + "/messages:send"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
		if err != nil {
			return SendResult{Status: sendRejected}
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		status, raw, retry, err := c.request(req)
		if err != nil {
			return SendResult{Status: sendRetry}
		}
		if status == http.StatusUnauthorized {
			c.invalidateAccessToken(token)
			if attempt == 0 {
				continue
			}
		}
		return fcmClassifyResponse(status, raw, retry, c.now())
	}
	return SendResult{Status: sendRejected}
}

func (c *fcmClient) request(req *http.Request) (int, []byte, string, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, fcmMaxResponse+1))
	if err != nil || len(body) > fcmMaxResponse {
		return 0, nil, "", errors.New("invalid FCM response size")
	}
	return resp.StatusCode, body, resp.Header.Get("Retry-After"), nil
}

func fcmClassifyResponse(status int, body []byte, retryText string, now time.Time) SendResult {
	if status == http.StatusOK {
		return SendResult{Status: sendAccepted}
	}
	if status == http.StatusNotFound && fcmUnregistered(body) {
		return SendResult{Status: sendInvalidToken}
	}
	if status == http.StatusTooManyRequests || status >= 500 {
		var delay time.Duration
		if seconds, err := strconv.ParseUint(retryText, 10, 32); err == nil {
			delay = time.Duration(seconds) * time.Second
		} else if deadline, err := http.ParseTime(retryText); err == nil {
			delay = max(0, deadline.Sub(now))
		}
		if status == http.StatusTooManyRequests && delay <= 0 {
			delay = time.Minute
		}
		return SendResult{Status: sendRetry, RetryAfter: delay}
	}
	return SendResult{Status: sendRejected}
}

func fcmUnregistered(body []byte) bool {
	var response struct {
		Error struct {
			Details []struct {
				Type string `json:"@type"`
				Code string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &response) != nil {
		return false
	}
	for _, detail := range response.Error.Details {
		if detail.Type == "type.googleapis.com/google.firebase.fcm.v1.FcmError" && detail.Code == "UNREGISTERED" {
			return true
		}
	}
	return false
}
