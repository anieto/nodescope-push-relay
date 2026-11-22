package main

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
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

const defaultNotificationTitle = "NodeScope"

// relayAlert writes the visible alert text. The title is the app's name,
// RELAY_NOTIFICATION_TITLE; an empty title means the default.
func relayAlert(title string, job Job) (string, string) {
	if title == "" {
		title = defaultNotificationTitle
	}
	var body string
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
	return title, body
}

// notificationTitle validates RELAY_NOTIFICATION_TITLE: one short line.
func notificationTitle(raw string) (string, error) {
	title := strings.TrimSpace(raw)
	if title == "" {
		return defaultNotificationTitle, nil
	}
	if utf8.RuneCountInString(title) > 64 || strings.IndexFunc(title, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r)
	}) >= 0 {
		return "", errors.New("RELAY_NOTIFICATION_TITLE must be one line of at most 64 characters")
	}
	return title, nil
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
		title, err := notificationTitle(getenv("RELAY_NOTIFICATION_TITLE"))
		if err != nil {
			return nil, err
		}
		topic := getenv("RELAY_APNS_TOPIC")
		if topic == "" {
			topic = "com.btdev.nodescope"
		}
		apns, err := newAPNsSender(getenv("RELAY_APNS_TEAM_ID"), getenv("RELAY_APNS_KEY_ID"), topic, getenv("RELAY_APNS_KEY_PATH"), providerEnvironment(mode, "apns"), title)
		if err != nil {
			return nil, err
		}
		fcm, err := newFCMSender(getenv("RELAY_FCM_PROJECT_ID"), getenv("RELAY_FCM_SERVICE_ACCOUNT_PATH"), providerEnvironment(mode, "fcm"), title)
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
