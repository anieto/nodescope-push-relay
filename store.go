package main

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	relayStateVersion         = 1
	relayCodeLifetime         = 15 * time.Minute
	relayProofLifetime        = 5 * time.Minute
	relaySubscriptionLifetime = 30 * 24 * time.Hour
	relayDedupRetention       = 24 * time.Hour
	relayEventLifetime        = time.Hour
	// Deliveries are kept only long enough to answer an analyzer's retry of
	// the same event idempotently: events live at most relayEventLifetime.
	relayDeliveryRetention = time.Hour
	relayPruneInterval     = 10 * time.Minute

	// Shared caps only bound memory and the state file. Each one sits well
	// above what per-owner quotas let a single installation, analyzer or
	// enrollment domain reach, so one owner cannot lock everyone else out.
	relayMaxAnalyzers             = 128  // active (not revoked)
	relayMaxAnalyzerRecords       = 1024 // including revoked
	relaySelfEnrollPerDomain      = 2    // per registrable domain per day
	relayMaxInstallations         = 2048
	relayMaxProofs                = 65536
	relayMaxUnusedProofs          = 8 // per installation
	relayMaxSubscriptions         = 8192
	relayMaxDeliveries            = 20000
	relayMaxDeliveriesPerAnalyzer = 500 // retained, all states
)

type enrollmentRecord struct {
	Origin    string
	ExpiresAt time.Time
	Used      bool
}

type analyzerRecord struct {
	Origin         string
	CredentialHash string
	Revoked        bool
	// EnrolledAt and SelfEnrolled are zero for records from before they
	// existed; such records never count toward the self-enrollment rate.
	EnrolledAt   time.Time
	SelfEnrolled bool
}

type installationRecord struct {
	Provider, Environment string
	Token, CredentialHash string
	Generation            uint64
	// LastActiveAt is the last registration, token update, link proof or
	// link. Zero for records from before it existed: Prune treats those as
	// active as of the first prune after the upgrade.
	LastActiveAt time.Time
}

type proofRecord struct {
	AnalyzerID, InstallationID string
	ExpiresAt                  time.Time
	BindingID, SubscriptionID  string
}

type subscriptionRecord struct {
	AnalyzerID, InstallationID, BindingID string
	ExpiresAt                             time.Time
	Revoked                               bool
}

type deliveryKey struct {
	AnalyzerID, SubscriptionID, EventID string
}

type deliveryRecord struct {
	ID, AnalyzerID, Status string
	Request                DeliveryRequest
	CreatedAt, NextAt      time.Time
	Attempts               int
}

type relayState struct {
	Version       int
	Codes         map[string]enrollmentRecord
	Analyzers     map[string]analyzerRecord
	Installations map[string]installationRecord
	Proofs        map[string]proofRecord
	Subscriptions map[string]subscriptionRecord
	Deliveries    map[string]deliveryRecord
}

type Store struct {
	mu           sync.Mutex
	path         string
	aead         cipher.AEAD
	mode         string
	now          func() time.Time
	state        relayState
	activeClaims map[string]uint64
	deliveryKeys map[deliveryKey]string
	// installationIdle removes installations with no active subscription
	// after this long without activity. Zero keeps them (the default):
	// clients must re-register on unknown_installation before it is enabled.
	installationIdle time.Duration
}

// SetInstallationIdle sets how long an installation without an active
// subscription is kept after its last activity. Zero disables removal.
func (s *Store) SetInstallationIdle(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.installationIdle = max(d, 0)
}

func OpenStore(path string, now func() time.Time) (*Store, error) {
	return openStore(path, now, nil, "simulate")
}

func openStore(path string, now func() time.Time, aead cipher.AEAD, mode string) (*Store, error) {
	if path == "" {
		return nil, storeError(503, "state_path_required")
	}
	if now == nil {
		now = time.Now
	}
	s := &Store{path: path, now: now, aead: aead, mode: mode, activeClaims: make(map[string]uint64)}
	if err := s.load(); err != nil {
		return nil, err
	}
	s.indexDeliveries()
	return s, nil
}

func (s *Store) encryptionPrefix() []byte {
	if s.mode == "production" {
		return []byte(productionStatePrefix)
	}
	return []byte(encryptedStatePrefix)
}

func (s *Store) load() error {
	info, err := os.Lstat(s.path)
	if errors.Is(err, os.ErrNotExist) {
		s.state = relayState{
			Version: relayStateVersion, Codes: make(map[string]enrollmentRecord),
			Analyzers: make(map[string]analyzerRecord), Installations: make(map[string]installationRecord),
			Proofs: make(map[string]proofRecord), Subscriptions: make(map[string]subscriptionRecord),
			Deliveries: make(map[string]deliveryRecord),
		}
		if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
			return storeError(503, "state_unavailable")
		}
		_, err = s.write(s.state)
		return err
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 64<<20 {
		return storeError(503, "state_unavailable")
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return storeError(503, "state_unavailable")
	}
	if s.aead != nil {
		data, err = decryptRelayState(s.aead, data, s.encryptionPrefix())
		if err != nil {
			return storeError(503, "state_decryption_failed")
		}
	}
	if json.Unmarshal(data, &s.state) != nil || s.state.Version != relayStateVersion ||
		s.state.Codes == nil || s.state.Analyzers == nil || s.state.Installations == nil ||
		s.state.Proofs == nil || s.state.Subscriptions == nil || s.state.Deliveries == nil {
		return storeError(503, "invalid_state")
	}
	return nil
}

func (s *Store) write(state relayState) (renamed bool, err error) {
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return false, storeError(503, "state_unavailable")
	}
	defer dir.Close()
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".relay-state-*")
	if err != nil {
		return false, storeError(503, "state_unavailable")
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	data, err := json.Marshal(state)
	if err != nil {
		return false, storeError(503, "state_unavailable")
	}
	if s.aead != nil {
		prefix := s.encryptionPrefix()
		data = s.aead.Seal(prefix, nil, data, prefix)
	}
	if _, err = tmp.Write(data); err != nil {
		return false, storeError(503, "state_unavailable")
	}
	if err = tmp.Sync(); err != nil {
		return false, storeError(503, "state_unavailable")
	}
	if err = tmp.Close(); err != nil {
		return false, storeError(503, "state_unavailable")
	}
	if err = os.Rename(tmp.Name(), s.path); err != nil {
		return false, storeError(503, "state_unavailable")
	}
	if err = dir.Sync(); err != nil {
		return true, storeError(503, "state_unavailable")
	}
	return true, nil
}

func (s *Store) indexDeliveries() {
	s.deliveryKeys = make(map[deliveryKey]string, len(s.state.Deliveries))
	for id, entry := range s.state.Deliveries {
		s.deliveryKeys[deliveryKey{entry.AnalyzerID, entry.Request.SubscriptionID, entry.Request.EventID}] = id
	}
}

// Call with the mutex held. A successful response always follows a synced snapshot.
func (s *Store) commit(next relayState) error {
	renamed, err := s.write(next)
	if renamed {
		s.state = next
		s.indexDeliveries()
	}
	return err
}

func storeError(status int, code string) *APIError {
	return &APIError{Status: status, Code: code}
}

func secret() string {
	var data [32]byte
	rand.Read(data[:])
	return base64.RawURLEncoding.EncodeToString(data[:])
}

func hashSecret(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func newID(prefix string) string { return prefix + "_" + secret() }

var (
	relayIDPattern     = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	relayPubkeyPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	relaySecretPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	relayTokenPattern  = regexp.MustCompile(`^[!-~]+$`)
)

func canonicalOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if len(raw) > 1024 || err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "" ||
		u.User != nil || (u.Path != "" && u.Path != "/") || u.RawPath != "" || u.ForceQuery ||
		u.RawQuery != "" || strings.Contains(raw, "#") {
		return "", storeError(400, "invalid_origin")
	}
	return "https://" + strings.ToLower(u.Host), nil
}

// Treat explicit and implicit standard HTTPS ports as one origin.
func enrollmentOriginKey(origin string) string {
	return strings.TrimSuffix(origin, ":443")
}

func (s *Store) IssueCode(origin string) (string, error) {
	origin, err := canonicalOrigin(origin)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	for _, analyzer := range s.state.Analyzers {
		if enrollmentOriginKey(analyzer.Origin) == enrollmentOriginKey(origin) && !analyzer.Revoked {
			return "", storeError(409, "analyzer_already_enrolled")
		}
	}
	next := s.state
	next.Codes = maps.Clone(next.Codes)
	for key, record := range next.Codes {
		if !record.ExpiresAt.Add(relayDedupRetention).After(now) {
			delete(next.Codes, key)
		}
	}
	if len(next.Codes) >= relayMaxAnalyzers*4 {
		return "", storeError(429, "enrollment_limit")
	}
	code := secret()
	next.Codes[hashSecret(code)] = enrollmentRecord{Origin: origin, ExpiresAt: now.Add(relayCodeLifetime)}
	if err := s.commit(next); err != nil {
		return "", err
	}
	return code, nil
}

func (s *Store) Enroll(code, requestID string) (Enrollment, error) {
	if !relaySecretPattern.MatchString(code) || !relayIDPattern.MatchString(requestID) {
		return Enrollment{}, storeError(400, "invalid_enrollment")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashSecret(code)
	record, exists := s.state.Codes[key]
	if !exists {
		return Enrollment{}, storeError(404, "unknown_enrollment")
	}
	if record.Used || !record.ExpiresAt.After(s.now()) {
		return Enrollment{}, storeError(410, "inactive_enrollment")
	}
	next := s.state
	next.Codes = maps.Clone(next.Codes)
	record.Used = true
	next.Codes[key] = record
	return s.enrollOrigin(next, record.Origin, secret(), false)
}

// enrollVerifiedOrigin creates an enrollment after the HTTP layer proves origin control.
func (s *Store) enrollVerifiedOrigin(origin, credential string) (Enrollment, error) {
	origin, err := selfEnrollmentOrigin(origin)
	if err != nil {
		return Enrollment{}, err
	}
	if _, valid := canonicalProofEncoding(credential, 32); !valid {
		return Enrollment{}, storeError(400, "invalid_enrollment")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enrollOrigin(s.state, origin, credential, true)
}

// enrollOrigin checks uniqueness and commits the state while the store is locked.
func (s *Store) enrollOrigin(next relayState, origin, credential string, allowRetry bool) (Enrollment, error) {
	credentialHash := hashSecret(credential)
	var existingID string
	originKey := enrollmentOriginKey(origin)
	now := s.now().UTC()
	domain := registrableDomain(origin)
	active, recentForDomain := 0, 0
	for id, record := range next.Analyzers {
		if !record.Revoked {
			active++
		}
		if record.SelfEnrolled && record.EnrolledAt.After(now.Add(-24*time.Hour)) && registrableDomain(record.Origin) == domain {
			recentForDomain++
		}
		if enrollmentOriginKey(record.Origin) == originKey && !record.Revoked {
			if allowRetry && record.CredentialHash == credentialHash {
				existingID = id
				continue
			}
			return Enrollment{}, storeError(409, "analyzer_already_enrolled")
		}
		if allowRetry && record.CredentialHash == credentialHash {
			return Enrollment{}, storeError(409, "sender_credential_already_used")
		}
	}
	if existingID != "" {
		return Enrollment{AnalyzerID: existingID, SenderCredential: credential}, nil
	}
	// allowRetry marks self-enrollment: one domain with wildcard DNS can
	// prove any number of origins, so its rate is bounded per domain.
	if allowRetry && recentForDomain >= relaySelfEnrollPerDomain {
		return Enrollment{}, storeError(429, "domain_enrollment_limit")
	}
	if active >= relayMaxAnalyzers || len(next.Analyzers) >= relayMaxAnalyzerRecords {
		return Enrollment{}, storeError(429, "analyzer_limit")
	}
	id := newID("an")
	next.Analyzers = maps.Clone(next.Analyzers)
	next.Analyzers[id] = analyzerRecord{Origin: origin, CredentialHash: credentialHash, EnrolledAt: now, SelfEnrolled: allowRetry}
	if err := s.commit(next); err != nil {
		return Enrollment{}, err
	}
	return Enrollment{AnalyzerID: id, SenderCredential: credential}, nil
}

func (s *Store) authenticateAnalyzer(credential string) (string, analyzerRecord, error) {
	if relaySecretPattern.MatchString(credential) {
		hash := hashSecret(credential)
		for id, record := range s.state.Analyzers {
			if record.CredentialHash == hash {
				return id, record, nil
			}
		}
	}
	return "", analyzerRecord{}, storeError(401, "invalid_credential")
}

func (s *Store) Analyzer(credential string) (Analyzer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, record, err := s.authenticateAnalyzer(credential)
	if err != nil {
		return Analyzer{}, err
	}
	if record.Revoked {
		return Analyzer{}, storeError(410, "analyzer_inactive")
	}
	return Analyzer{AnalyzerID: id, Origin: record.Origin, ContractVersion: 1}, nil
}

func (s *Store) RevokeAnalyzer(credential string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, record, err := s.authenticateAnalyzer(credential)
	if err != nil {
		return err
	}
	if record.Revoked {
		return nil
	}
	next := s.state
	next.Analyzers = maps.Clone(next.Analyzers)
	next.Subscriptions = maps.Clone(next.Subscriptions)
	next.Deliveries = maps.Clone(next.Deliveries)
	record.Revoked = true
	next.Analyzers[id] = record
	for subID, sub := range next.Subscriptions {
		if sub.AnalyzerID == id && !sub.Revoked {
			sub.Revoked = true
			next.Subscriptions[subID] = sub
		}
	}
	for jobID, job := range next.Deliveries {
		if job.AnalyzerID == id && job.Status == "queued" {
			job.Status = "cancelled"
			next.Deliveries[jobID] = job
		}
	}
	return s.commit(next)
}

func validEnvironment(provider, env string) bool {
	switch provider {
	case "apns":
		return env == "development" || env == "production"
	case "fcm":
		return env == "staging" || env == "production"
	default:
		return false
	}
}

func (s *Store) tokenClaimed(id, provider, env, token string) bool {
	for existingID, install := range s.state.Installations {
		if id != existingID && install.Provider == provider && install.Environment == env && install.Token == token {
			return true
		}
	}
	return false
}

// validProviderToken checks a push token's shape. Simulation accepts any
// printable token so tests and local runs can use readable fixtures.
func (s *Store) validProviderToken(provider, token string) bool {
	if len(token) > 4096 || !relayTokenPattern.MatchString(token) {
		return false
	}
	if s.mode == "simulate" {
		return true
	}
	switch provider {
	case "apns":
		return len(token) >= 64 && validAPNsDeviceToken(token)
	case "fcm":
		return len(token) >= 32 && fcmTokenPattern.MatchString(token)
	}
	return false
}

func (s *Store) RegisterInstallation(req InstallRequest) (Installation, error) {
	if !validEnvironment(req.Provider, req.Environment) || (s.mode != "simulate" && req.Environment != providerEnvironment(s.mode, req.Provider)) || !s.validProviderToken(req.Provider, req.Token) {
		return Installation{}, storeError(400, "invalid_installation")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokenClaimed("", req.Provider, req.Environment, req.Token) {
		return Installation{}, storeError(409, "token_already_registered")
	}
	if len(s.state.Installations) >= relayMaxInstallations {
		return Installation{}, storeError(429, "installation_limit")
	}
	id, credential := newID("inst"), secret()
	next := s.state
	next.Installations = maps.Clone(next.Installations)
	next.Installations[id] = installationRecord{
		Provider: req.Provider, Environment: req.Environment, Token: req.Token,
		CredentialHash: hashSecret(credential), Generation: 1, LastActiveAt: s.now().UTC(),
	}
	if err := s.commit(next); err != nil {
		return Installation{}, err
	}
	return Installation{InstallationID: id, InstallationCredential: credential}, nil
}

// authenticateInstallation answers 404 unknown_installation for an ID the
// relay does not hold (never issued, or removed as idle) so a client knows
// to register again, and 401 for a wrong credential. Installation IDs are
// 256-bit random values, so the distinction reveals nothing guessable.
func (s *Store) authenticateInstallation(id, credential string) (installationRecord, error) {
	record, exists := s.state.Installations[id]
	if !exists {
		return installationRecord{}, storeError(404, "unknown_installation")
	}
	if !relaySecretPattern.MatchString(credential) || record.CredentialHash != hashSecret(credential) {
		return installationRecord{}, storeError(401, "invalid_credential")
	}
	return record, nil
}

func (s *Store) UpdateToken(id, credential string, req TokenRequest) error {
	if len(req.Token) > 4096 || !relayTokenPattern.MatchString(req.Token) {
		return storeError(400, "invalid_token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, err := s.authenticateInstallation(id, credential)
	if err != nil {
		return err
	}
	if !s.validProviderToken(record.Provider, req.Token) {
		return storeError(400, "invalid_token")
	}
	now := s.now().UTC()
	if record.Token == req.Token {
		// Apps refresh their token on launch; count that as activity, but
		// write at most once a day for it.
		if s.installationIdle > 0 && now.Sub(record.LastActiveAt) >= 24*time.Hour {
			next := s.state
			next.Installations = maps.Clone(next.Installations)
			record.LastActiveAt = now
			next.Installations[id] = record
			return s.commit(next)
		}
		return nil
	}
	if s.tokenClaimed(id, record.Provider, record.Environment, req.Token) {
		return storeError(409, "token_already_registered")
	}
	next := s.state
	next.Installations = maps.Clone(next.Installations)
	record.Token = req.Token
	record.Generation++
	record.LastActiveAt = now
	next.Installations[id] = record
	return s.commit(next)
}

func (s *Store) LinkProof(id, credential, analyzerID string) (Proof, error) {
	if !relayIDPattern.MatchString(analyzerID) {
		return Proof{}, storeError(400, "invalid_analyzer")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	install, err := s.authenticateInstallation(id, credential)
	if err != nil {
		return Proof{}, err
	}
	if record, exists := s.state.Analyzers[analyzerID]; !exists || record.Revoked {
		return Proof{}, storeError(404, "unknown_analyzer")
	}
	now := s.now().UTC()
	next := s.state
	next.Proofs = maps.Clone(next.Proofs)
	pruneProofs(next.Proofs, now)
	unused := 0
	for _, record := range next.Proofs {
		if record.InstallationID == id && record.SubscriptionID == "" {
			unused++
		}
	}
	// The per-installation quota is what limits proofs; the shared cap only
	// bounds memory and sits far above installations × quota.
	if unused >= relayMaxUnusedProofs {
		return Proof{}, storeError(429, "link_proof_limit")
	}
	if len(next.Proofs) >= relayMaxProofs {
		return Proof{}, storeError(503, "service_unavailable")
	}
	value, expires := secret(), now.Add(relayProofLifetime)
	next.Proofs[hashSecret(value)] = proofRecord{InstallationID: id, AnalyzerID: analyzerID, ExpiresAt: expires}
	next.Installations = maps.Clone(next.Installations)
	install.LastActiveAt = now
	next.Installations[id] = install
	if err := s.commit(next); err != nil {
		return Proof{}, err
	}
	return Proof{Proof: value, ExpiresAt: expires}, nil
}

func subscriptionInfo(id string, record subscriptionRecord, now time.Time) Subscription {
	status := "active"
	if record.Revoked {
		status = "revoked"
	} else if !record.ExpiresAt.After(now) {
		status = "expired"
	}
	return Subscription{SubscriptionID: id, Status: status, ExpiresAt: record.ExpiresAt}
}

func cancelSubscription(state *relayState, id string) {
	sub := state.Subscriptions[id]
	sub.Revoked = true
	state.Subscriptions[id] = sub
	for jobID, job := range state.Deliveries {
		if job.Request.SubscriptionID == id && job.Status == "queued" {
			job.Status = "cancelled"
			state.Deliveries[jobID] = job
		}
	}
}

func (s *Store) Link(credential string, req LinkRequest) (Subscription, error) {
	if !relayIDPattern.MatchString(req.InstallationID) || !relayIDPattern.MatchString(req.BindingID) || !relaySecretPattern.MatchString(req.Proof) {
		return Subscription{}, storeError(400, "invalid_link")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	analyzerID, analyzer, err := s.authenticateAnalyzer(credential)
	if err != nil {
		return Subscription{}, err
	}
	if analyzer.Revoked {
		return Subscription{}, storeError(410, "analyzer_inactive")
	}
	key := hashSecret(req.Proof)
	proof, exists := s.state.Proofs[key]
	if !exists || proof.AnalyzerID != analyzerID || proof.InstallationID != req.InstallationID {
		return Subscription{}, storeError(404, "unknown_proof")
	}
	now := s.now().UTC()
	if proof.SubscriptionID != "" {
		if proof.BindingID != req.BindingID {
			return Subscription{}, storeError(409, "proof_binding_conflict")
		}
		record, exists := s.state.Subscriptions[proof.SubscriptionID]
		if !exists || record.Revoked || !record.ExpiresAt.After(now) {
			return Subscription{}, storeError(410, "subscription_inactive")
		}
		return subscriptionInfo(proof.SubscriptionID, record, now), nil
	}
	if !proof.ExpiresAt.After(now) {
		return Subscription{}, storeError(410, "proof_expired")
	}

	next := s.state
	next.Proofs = maps.Clone(next.Proofs)
	next.Subscriptions = maps.Clone(next.Subscriptions)
	next.Deliveries = maps.Clone(next.Deliveries)
	subID := ""
	activeSources := 0
	for id, sub := range next.Subscriptions {
		if !sub.ExpiresAt.Add(relayDedupRetention).After(now) {
			delete(next.Subscriptions, id)
			continue
		}
		if sub.InstallationID != req.InstallationID || sub.Revoked || !sub.ExpiresAt.After(now) {
			continue
		}
		if sub.AnalyzerID != analyzerID {
			activeSources++
		} else if sub.BindingID == req.BindingID {
			subID = id
		} else {
			cancelSubscription(&next, id)
		}
	}
	if subID == "" {
		if len(next.Subscriptions) >= relayMaxSubscriptions || activeSources >= 16 {
			return Subscription{}, storeError(429, "subscription_limit")
		}
		subID = newID("sub")
	}
	record := subscriptionRecord{
		AnalyzerID: analyzerID, InstallationID: req.InstallationID, BindingID: req.BindingID,
		ExpiresAt: now.Add(relaySubscriptionLifetime),
	}
	next.Subscriptions[subID] = record
	proof.BindingID, proof.SubscriptionID = req.BindingID, subID
	next.Proofs[key] = proof
	if install, ok := next.Installations[req.InstallationID]; ok {
		next.Installations = maps.Clone(next.Installations)
		install.LastActiveAt = now
		next.Installations[req.InstallationID] = install
	}
	if err := s.commit(next); err != nil {
		return Subscription{}, err
	}
	return subscriptionInfo(subID, record, now), nil
}

func (s *Store) RevokeSubscription(credential, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	analyzerID, analyzer, analyzerErr := s.authenticateAnalyzer(credential)
	record, exists := s.state.Subscriptions[id]
	if analyzerErr != nil {
		if !relaySecretPattern.MatchString(credential) {
			return storeError(401, "invalid_credential")
		}
		hash := hashSecret(credential)
		found := false
		for installID, install := range s.state.Installations {
			if install.CredentialHash == hash {
				found = true
				if !exists || record.InstallationID != installID {
					return storeError(404, "unknown_subscription")
				}
				break
			}
		}
		if !found {
			return storeError(401, "invalid_credential")
		}
	} else if !exists || record.AnalyzerID != analyzerID {
		return storeError(404, "unknown_subscription")
	} else if analyzer.Revoked {
		return storeError(410, "analyzer_inactive")
	}
	if record.Revoked {
		return nil
	}
	next := s.state
	next.Subscriptions = maps.Clone(next.Subscriptions)
	next.Deliveries = maps.Clone(next.Deliveries)
	cancelSubscription(&next, id)
	return s.commit(next)
}

func validDelivery(req DeliveryRequest, now time.Time) bool {
	switch req.Kind {
	case "node.not_heard", "node.heard_again", "node.battery_low", "node.battery_recovered":
	default:
		return false
	}
	return relayIDPattern.MatchString(req.EventID) && relayIDPattern.MatchString(req.SubscriptionID) &&
		relayPubkeyPattern.MatchString(req.NodePubkey) && !req.OccurredAt.IsZero() &&
		!req.OccurredAt.After(now.Add(time.Minute)) && req.ExpiresAt.After(req.OccurredAt) &&
		req.ExpiresAt.Sub(req.OccurredAt) <= relayEventLifetime
}

func (s *Store) Deliver(credential string, req DeliveryRequest) (Delivery, bool, error) {
	now := s.now().UTC()
	if !validDelivery(req, now) {
		return Delivery{}, false, storeError(400, "invalid_delivery")
	}
	req.OccurredAt, req.ExpiresAt = req.OccurredAt.UTC(), req.ExpiresAt.UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	analyzerID, analyzer, err := s.authenticateAnalyzer(credential)
	if err != nil {
		return Delivery{}, false, err
	}
	if analyzer.Revoked {
		return Delivery{}, false, storeError(410, "analyzer_inactive")
	}
	key := deliveryKey{analyzerID, req.SubscriptionID, req.EventID}
	if id, exists := s.deliveryKeys[key]; exists {
		existing := s.state.Deliveries[id]
		if req != existing.Request {
			return Delivery{}, false, storeError(409, "delivery_conflict")
		}
		status := existing.Status
		if status == "queued" && !req.ExpiresAt.After(now) {
			status = "expired"
		}
		return Delivery{DeliveryID: id, Status: status}, false, nil
	}
	sub, exists := s.state.Subscriptions[req.SubscriptionID]
	if !exists || sub.AnalyzerID != analyzerID {
		return Delivery{}, false, storeError(404, "unknown_subscription")
	}
	if sub.Revoked || !sub.ExpiresAt.After(now) {
		return Delivery{}, false, storeError(410, "subscription_inactive")
	}
	if !req.ExpiresAt.After(now) {
		return Delivery{}, false, storeError(410, "delivery_expired")
	}
	next := s.state
	next.Deliveries = maps.Clone(next.Deliveries)
	pruneDeliveries(next.Deliveries, now)
	analyzerCount, subCount, retained := 0, 0, 0
	hourAgo := now.Add(-time.Hour)
	for _, record := range next.Deliveries {
		if record.AnalyzerID != analyzerID {
			continue
		}
		retained++
		if record.CreatedAt.After(hourAgo) {
			analyzerCount++
			if record.Request.SubscriptionID == req.SubscriptionID {
				subCount++
			}
		}
	}
	if analyzerCount >= 120 || subCount >= 12 || retained >= relayMaxDeliveriesPerAnalyzer {
		return Delivery{}, false, storeError(429, "delivery_limit")
	}
	// Per-analyzer quotas are the limit; the shared cap only bounds memory.
	if len(next.Deliveries) >= relayMaxDeliveries {
		return Delivery{}, false, storeError(503, "service_unavailable")
	}
	id := newID("job")
	next.Deliveries[id] = deliveryRecord{ID: id, AnalyzerID: analyzerID, Status: "queued", Request: req, CreatedAt: now, NextAt: now}
	if err := s.commit(next); err != nil {
		return Delivery{}, false, err
	}
	return Delivery{DeliveryID: id, Status: "queued"}, true, nil
}

func (s *Store) Next() (Job, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	var selected deliveryRecord
	var selectedSub subscriptionRecord
	var selectedInstall installationRecord
	for id, record := range s.state.Deliveries {
		if _, claimed := s.activeClaims[id]; claimed || record.Status != "queued" ||
			record.NextAt.After(now) || !record.Request.ExpiresAt.After(now) {
			continue
		}
		sub, exists := s.state.Subscriptions[record.Request.SubscriptionID]
		if !exists || sub.Revoked || !sub.ExpiresAt.After(now) || s.state.Analyzers[record.AnalyzerID].Revoked {
			continue
		}
		install := s.state.Installations[sub.InstallationID]
		if install.Token == "" {
			continue
		}
		if selected.ID == "" || record.NextAt.Before(selected.NextAt) ||
			record.NextAt.Equal(selected.NextAt) && id < selected.ID {
			selected, selectedSub, selectedInstall = record, sub, install
		}
	}
	if selected.ID == "" {
		return Job{}, false, nil
	}
	s.activeClaims[selected.ID] = selectedInstall.Generation
	return Job{
		DeliveryID: selected.ID, AnalyzerID: selected.AnalyzerID, InstallationID: selectedSub.InstallationID,
		TokenGeneration: selectedInstall.Generation, Provider: selectedInstall.Provider,
		Environment: selectedInstall.Environment, Token: selectedInstall.Token, Request: selected.Request,
	}, true, nil
}

func (s *Store) Finish(job Job, result SendResult) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation, claimed := s.activeClaims[job.DeliveryID]; !claimed || generation != job.TokenGeneration {
		return nil
	}
	delete(s.activeClaims, job.DeliveryID)
	record, exists := s.state.Deliveries[job.DeliveryID]
	if !exists || record.Status != "queued" {
		return nil
	}
	now := s.now().UTC()
	next := s.state
	next.Deliveries = maps.Clone(next.Deliveries)
	switch result.Status {
	case sendAccepted:
		record.Status = "accepted"
	case sendInvalidToken:
		install := next.Installations[job.InstallationID]
		if install.Generation != job.TokenGeneration {
			record = retryDelivery(record, now, 0)
		} else {
			next.Installations = maps.Clone(next.Installations)
			install.Token = ""
			next.Installations[job.InstallationID] = install
			record.Status = "invalid_token"
		}
	case sendRetry:
		record = retryDelivery(record, now, result.RetryAfter)
	default:
		record.Status = "rejected"
	}
	next.Deliveries[job.DeliveryID] = record
	return s.commit(next)
}

func retryDelivery(record deliveryRecord, now time.Time, minimum time.Duration) deliveryRecord {
	delay := min(5*time.Minute, (5*time.Second)<<min(record.Attempts, 6))
	record.NextAt = now.Add(max(delay, minimum))
	record.Attempts++
	if record.Attempts >= 12 || !record.NextAt.Before(record.Request.ExpiresAt) {
		record.Status = "retry_exhausted"
	}
	return record
}

var fcmTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_:-]+$`)

// registrableDomain approximates an origin's registrable domain (eTLD+1)
// without the public suffix list: the last two labels, or the last three
// under a two-letter country code with a common second-level label
// (example.co.uk). Shared hosting suffixes such as duckdns.org count as
// one domain, so their users share the per-domain self-enrollment rate.
func registrableDomain(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return origin
	}
	labels := strings.Split(strings.ToLower(u.Hostname()), ".")
	n := len(labels)
	if n <= 2 {
		return strings.Join(labels, ".")
	}
	if len(labels[n-1]) == 2 {
		switch labels[n-2] {
		case "co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go":
			return strings.Join(labels[n-3:], ".")
		}
	}
	return strings.Join(labels[n-2:], ".")
}

// pruneProofs drops unused proofs once expired and used ones after the
// retention that lets an analyzer retry its link idempotently.
func pruneProofs(proofs map[string]proofRecord, now time.Time) bool {
	changed := false
	for key, record := range proofs {
		expired := !record.ExpiresAt.After(now)
		if (record.SubscriptionID == "" && expired) || !record.ExpiresAt.Add(relayDedupRetention).After(now) {
			delete(proofs, key)
			changed = true
		}
	}
	return changed
}

// pruneDeliveries drops deliveries an hour after their event expired; by
// then no analyzer retry of the event is accepted anyway.
func pruneDeliveries(deliveries map[string]deliveryRecord, now time.Time) bool {
	changed := false
	for id, record := range deliveries {
		if !record.Request.ExpiresAt.Add(relayDeliveryRetention).After(now) {
			delete(deliveries, id)
			changed = true
		}
	}
	return changed
}

// Prune removes expired records: enrollment codes, proofs, subscriptions a
// day after they ended, deliveries, and (when enabled) idle installations
// with no active subscription. It runs periodically so expired data is
// removed even when no request touches that part of the state.
func (s *Store) Prune() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().UTC()
	next := s.state
	next.Codes = maps.Clone(next.Codes)
	next.Proofs = maps.Clone(next.Proofs)
	next.Subscriptions = maps.Clone(next.Subscriptions)
	next.Deliveries = maps.Clone(next.Deliveries)
	next.Installations = maps.Clone(next.Installations)
	changed := false
	for key, record := range next.Codes {
		if !record.ExpiresAt.Add(relayDedupRetention).After(now) {
			delete(next.Codes, key)
			changed = true
		}
	}
	if pruneProofs(next.Proofs, now) {
		changed = true
	}
	for id, sub := range next.Subscriptions {
		if !sub.ExpiresAt.Add(relayDedupRetention).After(now) {
			delete(next.Subscriptions, id)
			changed = true
		}
	}
	if pruneDeliveries(next.Deliveries, now) {
		changed = true
	}
	active := make(map[string]bool)
	for _, sub := range next.Subscriptions {
		if !sub.Revoked && sub.ExpiresAt.After(now) {
			active[sub.InstallationID] = true
		}
	}
	for id, install := range next.Installations {
		if install.LastActiveAt.IsZero() {
			install.LastActiveAt = now
			next.Installations[id] = install
			changed = true
			continue
		}
		if s.installationIdle > 0 && !active[id] && now.Sub(install.LastActiveAt) >= s.installationIdle {
			if _, claimed := s.activeClaimsFor(id); claimed {
				continue
			}
			delete(next.Installations, id)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.commit(next)
}

// activeClaimsFor reports whether a delivery for installation id is being
// sent right now. Call with the mutex held.
func (s *Store) activeClaimsFor(id string) (string, bool) {
	for deliveryID := range s.activeClaims {
		if record, ok := s.state.Deliveries[deliveryID]; ok {
			if sub, ok := s.state.Subscriptions[record.Request.SubscriptionID]; ok && sub.InstallationID == id {
				return deliveryID, true
			}
		}
	}
	return "", false
}
