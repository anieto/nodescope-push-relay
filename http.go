package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const relayMaxRequest = 8 << 10

type relayErrorResponse struct {
	Error struct {
		Code string `json:"code"`
	} `json:"error"`
}

type relayHTTP struct {
	store                *Store
	operator             [sha256.Size]byte
	operatorSet          bool
	enrollLimit          relayRequestLimit
	registerLimit        relayRequestLimit
	selfEnrollLimit      relayRequestLimit
	selfEnrollSlots      chan struct{}
	fetchEnrollmentProof enrollmentProofFetcher
}

// relayRequestLimit bounds public writes independently. It uses a single
// per-process window per endpoint so client-supplied addresses cannot create
// unbounded state or bypass the limit behind a reverse proxy.
type relayRequestLimit struct {
	mu       sync.Mutex
	limit    int
	count    int
	deadline time.Time
}

func (l *relayRequestLimit) allow(now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !now.Before(l.deadline) {
		l.deadline = now.Add(time.Minute)
		l.count = 0
	}
	if l.count >= l.limit {
		return l.deadline.Sub(now)
	}
	l.count++
	return 0
}

func NewHandler(store *Store, operatorToken string) http.Handler {
	return newRelayHandler(store, operatorToken, nil)
}

func newRelayHandler(store *Store, operatorToken string, fetchProof enrollmentProofFetcher) http.Handler {
	api := &relayHTTP{
		store:                store,
		operator:             sha256.Sum256([]byte(operatorToken)),
		operatorSet:          operatorToken != "",
		enrollLimit:          relayRequestLimit{limit: 30},
		registerLimit:        relayRequestLimit{limit: 60},
		selfEnrollLimit:      relayRequestLimit{limit: 12},
		selfEnrollSlots:      make(chan struct{}, 3),
		fetchEnrollmentProof: fetchProof,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", relayMethod(http.MethodGet, func(w http.ResponseWriter, _ *http.Request) {
		relayJSON(w, http.StatusOK, struct {
			Status string `json:"status"`
		}{"ok"})
	}))
	mux.HandleFunc("/v1/operator/enrollment-codes", relayMethod(http.MethodPost, api.issueCode))
	mux.HandleFunc("/v1/analyzers/enroll", relayMethod(http.MethodPost, api.enroll))
	if fetchProof != nil {
		mux.HandleFunc("/v1/analyzers/self-enroll", relayMethod(http.MethodPost, api.selfEnroll))
	}
	mux.HandleFunc("/v1/analyzer", api.analyzer)
	mux.HandleFunc("/v1/installations", relayMethod(http.MethodPost, api.register))
	mux.HandleFunc("/v1/installations/{id}/token", relayMethod(http.MethodPut, api.updateToken))
	mux.HandleFunc("/v1/installations/{id}/link-proofs", relayMethod(http.MethodPost, api.proof))
	mux.HandleFunc("/v1/subscriptions", relayMethod(http.MethodPost, api.link))
	mux.HandleFunc("/v1/subscriptions/{id}", relayMethod(http.MethodDelete, api.revoke))
	mux.HandleFunc("/v1/deliveries", relayMethod(http.MethodPost, api.deliver))
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		relayError(w, http.StatusNotFound, "not_found")
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

func relayMethod(method string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			relayError(w, http.StatusMethodNotAllowed, "method_not_allowed")
			return
		}
		next(w, r)
	}
}

func relayJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func relayError(w http.ResponseWriter, status int, code string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	var body relayErrorResponse
	body.Error.Code = code
	relayJSON(w, status, body)
}

func relayRetryAfter(w http.ResponseWriter, retry time.Duration) {
	if retry <= 0 {
		retry = time.Minute
	}
	seconds := (retry-1)/time.Second + 1
	w.Header().Set("Retry-After", strconv.FormatInt(int64(seconds), 10))
}

func relayStoreError(w http.ResponseWriter, err error) {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		if apiErr.Status == http.StatusTooManyRequests {
			relayRetryAfter(w, time.Minute)
		}
		relayError(w, apiErr.Status, apiErr.Code)
		return
	}
	relayError(w, http.StatusServiceUnavailable, "service_unavailable")
}

func relayDecode[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var result *T
	var empty T
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		relayError(w, http.StatusBadRequest, "invalid_request")
		return empty, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, relayMaxRequest)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil || result == nil {
		relayError(w, http.StatusBadRequest, "invalid_request")
		return empty, false
	}
	if err := decoder.Decode(&empty); !errors.Is(err, io.EOF) {
		relayError(w, http.StatusBadRequest, "invalid_request")
		return empty, false
	}
	return *result, true
}

func relayBearer(w http.ResponseWriter, r *http.Request) (string, bool) {
	headers := r.Header.Values("Authorization")
	if len(headers) == 1 && len(headers[0]) <= 520 {
		parts := strings.Fields(headers[0])
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") && !strings.Contains(parts[1], ",") {
			return parts[1], true
		}
	}
	relayError(w, http.StatusUnauthorized, "invalid_credential")
	return "", false
}

func relayPublicRate(w http.ResponseWriter, limit *relayRequestLimit) bool {
	if retry := limit.allow(time.Now()); retry > 0 {
		relayRetryAfter(w, retry)
		relayError(w, http.StatusTooManyRequests, "rate_limited")
		return false
	}
	return true
}

func (api *relayHTTP) issueCode(w http.ResponseWriter, r *http.Request) {
	if !api.operatorSet {
		relayError(w, http.StatusNotFound, "not_found")
		return
	}
	credential, ok := relayBearer(w, r)
	if !ok {
		return
	}
	got := sha256.Sum256([]byte(credential))
	if subtle.ConstantTimeCompare(got[:], api.operator[:]) != 1 {
		relayError(w, http.StatusUnauthorized, "invalid_credential")
		return
	}
	req, ok := relayDecode[struct {
		Origin string `json:"origin"`
	}](w, r)
	if !ok {
		return
	}
	code, err := api.store.IssueCode(req.Origin)
	if err != nil {
		relayStoreError(w, err)
		return
	}
	relayJSON(w, http.StatusCreated, struct {
		Code string `json:"code"`
	}{code})
}

func (api *relayHTTP) enroll(w http.ResponseWriter, r *http.Request) {
	if !relayPublicRate(w, &api.enrollLimit) {
		return
	}
	req, ok := relayDecode[struct {
		Code      string `json:"code"`
		RequestID string `json:"request_id"`
	}](w, r)
	if !ok {
		return
	}
	result, err := api.store.Enroll(req.Code, req.RequestID)
	if err != nil {
		relayStoreError(w, err)
		return
	}
	relayJSON(w, http.StatusCreated, result)
}

func (api *relayHTTP) analyzer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodDelete {
		w.Header().Set("Allow", "GET, DELETE")
		relayError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	credential, ok := relayBearer(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodDelete {
		if err := api.store.RevokeAnalyzer(credential); err != nil {
			relayStoreError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	result, err := api.store.Analyzer(credential)
	if err != nil {
		relayStoreError(w, err)
		return
	}
	relayJSON(w, http.StatusOK, result)
}

func (api *relayHTTP) register(w http.ResponseWriter, r *http.Request) {
	if !relayPublicRate(w, &api.registerLimit) {
		return
	}
	req, ok := relayDecode[InstallRequest](w, r)
	if !ok {
		return
	}
	result, err := api.store.RegisterInstallation(req)
	if err != nil {
		relayStoreError(w, err)
		return
	}
	relayJSON(w, http.StatusCreated, result)
}

func (api *relayHTTP) updateToken(w http.ResponseWriter, r *http.Request) {
	credential, ok := relayBearer(w, r)
	if !ok {
		return
	}
	req, ok := relayDecode[TokenRequest](w, r)
	if !ok {
		return
	}
	if err := api.store.UpdateToken(r.PathValue("id"), credential, req); err != nil {
		relayStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (api *relayHTTP) proof(w http.ResponseWriter, r *http.Request) {
	credential, ok := relayBearer(w, r)
	if !ok {
		return
	}
	req, ok := relayDecode[struct {
		AnalyzerID string `json:"analyzer_id"`
	}](w, r)
	if !ok {
		return
	}
	result, err := api.store.LinkProof(r.PathValue("id"), credential, req.AnalyzerID)
	if err != nil {
		relayStoreError(w, err)
		return
	}
	relayJSON(w, http.StatusCreated, result)
}

func (api *relayHTTP) link(w http.ResponseWriter, r *http.Request) {
	credential, ok := relayBearer(w, r)
	if !ok {
		return
	}
	req, ok := relayDecode[LinkRequest](w, r)
	if !ok {
		return
	}
	result, err := api.store.Link(credential, req)
	if err != nil {
		relayStoreError(w, err)
		return
	}
	relayJSON(w, http.StatusCreated, result)
}

func (api *relayHTTP) revoke(w http.ResponseWriter, r *http.Request) {
	credential, ok := relayBearer(w, r)
	if !ok {
		return
	}
	if err := api.store.RevokeSubscription(credential, r.PathValue("id")); err != nil {
		relayStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (api *relayHTTP) deliver(w http.ResponseWriter, r *http.Request) {
	credential, ok := relayBearer(w, r)
	if !ok {
		return
	}
	req, ok := relayDecode[DeliveryRequest](w, r)
	if !ok {
		return
	}
	result, created, err := api.store.Deliver(credential, req)
	if err != nil {
		relayStoreError(w, err)
		return
	}
	if created {
		relayJSON(w, http.StatusAccepted, result)
		return
	}
	relayJSON(w, http.StatusOK, result)
}
