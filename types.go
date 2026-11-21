package main

import "time"

type APIError struct {
	Status int
	Code   string
}

func (err *APIError) Error() string { return err.Code }

type Enrollment struct {
	AnalyzerID       string `json:"analyzer_id"`
	SenderCredential string `json:"sender_credential"`
}

type Analyzer struct {
	AnalyzerID      string `json:"analyzer_id"`
	Origin          string `json:"origin"`
	ContractVersion int    `json:"contract_version"`
}

type InstallRequest struct {
	Provider    string `json:"provider"`
	Token       string `json:"token"`
	Environment string `json:"environment"`
}

type Installation struct {
	InstallationID         string `json:"installation_id"`
	InstallationCredential string `json:"installation_credential"`
}

type TokenRequest struct {
	Token string `json:"token"`
}

type Proof struct {
	Proof     string    `json:"proof"`
	ExpiresAt time.Time `json:"expires_at"`
}

type LinkRequest struct {
	InstallationID string `json:"installation_id"`
	BindingID      string `json:"binding_id"`
	Proof          string `json:"proof"`
}

type Subscription struct {
	SubscriptionID string    `json:"subscription_id"`
	Status         string    `json:"status"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type DeliveryRequest struct {
	EventID        string    `json:"event_id"`
	SubscriptionID string    `json:"subscription_id"`
	Kind           string    `json:"kind"`
	NodePubkey     string    `json:"node_pubkey"`
	NodeName       string    `json:"node_name,omitempty"`
	OccurredAt     time.Time `json:"occurred_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type Delivery struct {
	DeliveryID string `json:"delivery_id"`
	Status     string `json:"status"`
}

type Job struct {
	DeliveryID      string
	AnalyzerID      string
	InstallationID  string
	TokenGeneration uint64
	Provider        string
	Environment     string
	Token           string
	Request         DeliveryRequest
}

type SendResult struct {
	Status     string
	RetryAfter time.Duration
}

const (
	sendAccepted     = "accepted"
	sendRetry        = "retry"
	sendInvalidToken = "invalid_token"
	sendRejected     = "rejected"
)
