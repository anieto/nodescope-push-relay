package main

import (
	"strings"
	"testing"
)

func TestRelayAlertUsesOptionalNodeName(t *testing.T) {
	cases := []struct{ kind, name, body string }{
		{"node.not_heard", " Café\nRepeater ", "Your analyzer hasn't heard Café Repeater recently."},
		{"node.heard_again", "Milliways 1W", "Your analyzer heard Milliways 1W again."},
		{"node.battery_low", "Milliways 1W", "Milliways 1W reported low battery."},
		{"node.battery_recovered", "Milliways 1W", "Battery reading recovered for Milliways 1W."},
		{"node.heard_again", "", "Your analyzer heard a watched node again."},
		{"node.not_heard", "\u202e\t", "Your analyzer hasn't heard a watched node recently."},
		{"node.battery_low", strings.Repeat("界", 81), strings.Repeat("界", 80) + "… reported low battery."},
	}
	for _, tc := range cases {
		title, body := relayAlert("", Job{Request: DeliveryRequest{Kind: tc.kind, NodeName: tc.name}})
		if title != "NodeScope" || body != tc.body {
			t.Errorf("relayAlert(%q, %q) = (%q, %q), want NodeScope, %q", tc.kind, tc.name, title, body, tc.body)
		}
	}
}

func TestNotificationTitleIsConfigurable(t *testing.T) {
	if title, body := relayAlert("Mesh Alerts", Job{Request: DeliveryRequest{Kind: "node.battery_low"}}); title != "Mesh Alerts" || body != "A watched node reported low battery." {
		t.Fatalf("custom title: %q, %q", title, body)
	}
	for raw, want := range map[string]string{"": "NodeScope", "  Mesh Alerts ": "Mesh Alerts", strings.Repeat("a", 64): strings.Repeat("a", 64)} {
		if got, err := notificationTitle(raw); err != nil || got != want {
			t.Errorf("notificationTitle(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{strings.Repeat("a", 65), "two\nlines", "bidi‮"} {
		if _, err := notificationTitle(raw); err == nil {
			t.Errorf("notificationTitle(%q) accepted", raw)
		}
	}
}
