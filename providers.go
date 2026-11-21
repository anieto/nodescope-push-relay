package main

import (
	"context"
	"errors"
	"strings"
	"unicode"
)

func relayMetadata(job Job) map[string]string {
	return map[string]string{
		"version":         "1",
		"analyzer_id":     job.AnalyzerID,
		"subscription_id": job.Request.SubscriptionID,
		"event_id":        job.Request.EventID,
		"kind":            job.Request.Kind,
		"node_pubkey":     job.Request.NodePubkey,
	}
}

func relayAlert(job Job) (title, body string) {
	title = "NodeScope"
	name := relayDisplayName(job.Request.NodeName)
	if name != "" {
		switch job.Request.Kind {
		case "node.not_heard":
			return title, "Your analyzer hasn't heard " + name + " recently."
		case "node.heard_again":
			return title, "Your analyzer heard " + name + " again."
		case "node.battery_low":
			return title, name + " reported low battery."
		case "node.battery_recovered":
			return title, "Battery reading recovered for " + name + "."
		}
	}
	switch job.Request.Kind {
	case "node.not_heard":
		body = "Your analyzer hasn't heard a watched node recently."
	case "node.heard_again":
		body = "Your analyzer heard a watched node again."
	case "node.battery_low":
		body = "A watched node reported low battery."
	case "node.battery_recovered":
		body = "A watched node's battery reading recovered."
	default:
		body = "A watched node changed state."
	}
	return
}

// Keep community-provided names on one line and short enough for a notification.
func relayDisplayName(name string) string {
	const maxRunes = 80
	name = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return ' '
		}
		return r
	}, name)), " ")
	count := 0
	for index := range name {
		if count == maxRunes {
			return strings.TrimSpace(name[:index]) + "…"
		}
		count++
	}
	return name
}

func resolveSendPush(mode string, getenv func(string) string) (sendPush, error) {
	switch mode {
	case "", "simulate":
		return simulatePush, nil
	case "staging", "production":
		topic := getenv("RELAY_APNS_TOPIC")
		if topic == "" {
			topic = "com.btdev.nodescope"
		}
		apns, err := newAPNsSender(getenv("RELAY_APNS_TEAM_ID"), getenv("RELAY_APNS_KEY_ID"), topic, getenv("RELAY_APNS_KEY_PATH"), providerEnvironment(mode, "apns"))
		if err != nil {
			return nil, err
		}
		fcm, err := newFCMSender(getenv("RELAY_FCM_PROJECT_ID"), getenv("RELAY_FCM_SERVICE_ACCOUNT_PATH"), providerEnvironment(mode, "fcm"))
		if err != nil {
			return nil, err
		}
		return func(ctx context.Context, job Job) SendResult {
			switch {
			case job.Provider == "apns" && job.Environment == providerEnvironment(mode, "apns"):
				return apns(ctx, job)
			case job.Provider == "fcm" && job.Environment == providerEnvironment(mode, "fcm"):
				return fcm(ctx, job)
			default:
				return SendResult{Status: sendRejected}
			}
		}, nil
	default:
		return nil, errors.New("RELAY_MODE must be simulate, staging, or production")
	}
}

func providerEnvironment(mode, provider string) string {
	if mode == "production" {
		return "production"
	}
	if provider == "apns" {
		return "development"
	}
	return "staging"
}
